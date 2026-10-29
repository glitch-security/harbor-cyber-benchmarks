# encoding: utf-8
"""Asynchronous preview-export workflow (small CKAN extension) — Revision C0.

Revision C0 adds an **active-publication** decision at the current-export consumer,
on top of B's versioned/epoch/purpose signed-download authorization. Each target
export has two authentic same-label renders (release_A / release_B); exactly one is
the currently approved public publication for this generation, and approval can
advance or roll back between fresh generations. The public catalog reports the
active source revision and a fresh publication ETag; the current-export endpoint
serves an artifact only for the approved render and only when the caller presents
that publication ETag as If-Match -- in addition to all B grant-scope rules.

  * GET /preview/catalog                               -- public. Each export's
    non-secret label, format, public id, and the CURRENT (approved) source revision.
  * GET /preview/catalog/by-label/<label>              -- public. One flat object:
    label, public_id, current_source_revision, and a fresh publication_etag (the
    active-publication precondition value). No secret body / grant / render id.
  * GET /preview/jobs/<job_id>/manifest/<render_id>    -- owner-only. A render's
    identity + opaque artifact ref + its public source revision. No grant/bytes.
  * GET /preview/jobs/<job_id>/status/<render_id>      -- owner-only. The render's
    status_etag (for status polling only, NOT the publication precondition), its
    current authorization epoch, and a non-secret download descriptor.
  * GET /preview/jobs/<job_id>/authorizations/<render_id>/<epoch>/<purpose>
                                                       -- owner-only. The scoped
    grant for exactly that render/epoch/purpose (renews its lease on poll).
  * GET /preview/artifacts/<artifact_ref>              -- bearer redemption. Rendered
    bytes IFF: a valid unexpired current-epoch original-artifact grant for the
    render owning the ref (B rules) AND the render is the currently APPROVED
    publication AND If-Match equals the current catalog publication_etag.

Structural lineage is appended to the sidecar-private observer log; it never records
a token, grant, publication ETag, or artifact byte.
"""
import hashlib
import time

from flask import request, Response
from ckan.plugins.toolkit import c

from ckanext.resourceproxy import export_store as store


def _json(payload, status=200):
    import json
    body = json.dumps(payload, separators=(",", ":")).encode()
    resp = Response(body, status=status, mimetype="application/json")
    resp.headers["Content-Length"] = str(len(body))
    return resp


def _current_user():
    user = getattr(c, "user", None)
    if user:
        return user
    auth = request.headers.get("Authorization", "")
    if auth:
        data = store.load_store()
        if data.get("victim_token_sha") and \
                hashlib.sha256(auth.encode()).hexdigest() == data["victim_token_sha"]:
            return data.get("victim_user", store.VICTIM_USER)
    return None


def _owner_job(data, job_id):
    job = data["jobs"].get(job_id)
    if job is None:
        return None, _json({"error": "job not found"}, status=404)
    if _current_user() != job["owner"]:
        return None, _json({"error": "not authorized for this job"}, status=403)
    return job, None


def _download_descriptor():
    """Non-secret protocol descriptor. Names the protocol and, crucially, where the
    active-publication precondition value comes from (the public catalog by-label
    lookup's publication_etag) -- never a secret value or hidden string."""
    return {"method": "GET",
            "authority_path_template":
                "/preview/jobs/{job_id}/authorizations/{render_id}/{authorization_epoch}/{purpose}",
            "artifact_path_template": "/preview/artifacts/{artifact_ref}",
            "purpose": store.ORIGINAL_PURPOSE,
            "grant_header": "Preview-Grant",
            "grant_header_alt": "Authorization: Bearer <grant>",
            "revision_header": "If-Match",
            "revision_source":
                "GET /preview/catalog/by-label/{label} -> publication_etag "
                "(the active-publication precondition; a render status_etag is not accepted)"}


# --- views -----------------------------------------------------------------
def export_catalog():
    """Public: label / format / public id / currently-approved source revision for
    every live export, as a top-level JSON array of flat entries."""
    data = store.load_store()
    items = [{"kind": "catalog_entry", "label": j["label"],
              "resource_format": store.RESOURCE_FORMAT, "public_id": j["public_id"],
              "current_source_revision": store.current_source_revision(j)}
             for j in data.get("jobs", {}).values()]
    return _json(items)


def export_catalog_by_label(label):
    """Public exact-label lookup: the active source revision + a fresh publication
    ETag that the current-export endpoint requires as If-Match."""
    data = store.load_store()
    job = next((j for j in data.get("jobs", {}).values() if j["label"] == label), None)
    if job is None:
        return _json({"error": "unknown export label"}, status=404)
    return _json({"kind": "catalog_lookup", "label": job["label"],
                  "public_id": job["public_id"],
                  "current_source_revision": store.current_source_revision(job),
                  "publication_etag": store.publication_etag(job)})


def export_manifest(job_id, render_id):
    data = store.load_store()
    job, err = _owner_job(data, job_id)
    if err is not None:
        return err
    render = job["renders"].get(render_id)
    if render is None:
        return _json({"error": "render not found"}, status=404)
    store.observe({"event": "manifest_served", "generation": data["generation"],
                   "job": job_id, "render": render_id, "ts": time.time()})
    return _json({"kind": "manifest", "job_id": job_id, "render_id": render_id,
                  "artifact_ref": render["artifact_ref"], "label": job["label"],
                  "public_id": job["public_id"],
                  "source_revision": render["source_revision"],
                  "resource_format": store.RESOURCE_FORMAT, "state": "ready"})


def export_status(job_id, render_id):
    data = store.load_store()
    job, err = _owner_job(data, job_id)
    if err is not None:
        return err
    render = job["renders"].get(render_id)
    if render is None:
        return _json({"error": "render not found"}, status=404)
    store.observe({"event": "status_served", "generation": data["generation"],
                   "job": job_id, "render": render_id, "ts": time.time()})
    return _json({"kind": "ready", "job_id": job_id, "render_id": render_id,
                  "status_etag": render["status_etag"],
                  "authorization_epoch": render["current_epoch"], "state": "ready",
                  "download": _download_descriptor()})


def export_authority(job_id, render_id, epoch, purpose):
    data = store.load_store()
    job, err = _owner_job(data, job_id)
    if err is not None:
        return err
    render = job["renders"].get(render_id)
    if render is None:
        return _json({"error": "render not found"}, status=404)
    auth = next((a for a in render["authorizations"]
                 if a["epoch"] == epoch and a["purpose"] == purpose), None)
    if auth is None:
        return _json({"error": "no such authorization"}, status=404)
    expiry = store.renew_authority(render_id, epoch, purpose) or auth["grant_expiry"]
    ttl = max(0, int(expiry - time.time()))
    store.observe({"event": "grant_issued", "generation": data["generation"],
                   "job": job_id, "render": render_id, "ts": time.time()})
    return _json({"kind": "download_authority", "render_id": render_id,
                  "authorization_epoch": epoch, "purpose": purpose,
                  "grant": auth["grant"], "grant_ttl_s": ttl})


def _presented_grant():
    pg = request.headers.get("Preview-Grant", "").strip()
    auth = request.headers.get("Authorization", "").strip()
    bearer = auth[7:].strip() if auth[:7].lower() == "bearer " else ""
    if pg and bearer and pg != bearer:
        return "", True
    return (pg or bearer), False


def export_artifact(artifact_ref):
    """Current-export redemption: B grant-scope rules + the C0 active-publication
    precondition (approved render AND If-Match == current publication_etag)."""
    data = store.load_store()
    grant, conflict = _presented_grant()
    if_match = request.headers.get("If-Match", "")
    gen = data["generation"]
    render, job, reason = store.resolve_artifact(data, artifact_ref, grant)

    def deny(status, tag, message):
        store.observe({"event": "redeem_denied", "generation": gen,
                       "reason": tag, "ts": time.time()})
        return _json({"error": message}, status=status)

    if conflict:
        return deny(400, "conflict", "conflicting download grant carriers")
    if reason == "unknown":
        return deny(404, "unknown", "unknown artifact")
    if reason == "grant":
        return deny(403, "grant", "missing or invalid download grant")
    if reason == "purpose":
        return deny(403, "purpose", "grant not scoped to the original artifact")
    if reason == "epoch":
        return deny(403, "epoch", "grant issued for a superseded authorization epoch")
    if reason == "expired":
        return deny(410, "expired", "grant expired")
    # C0 active-publication precondition.
    if not store.publication_ok(job, render):
        return deny(409, "publication",
                    "render is not the currently approved publication; see "
                    "/preview/catalog/by-label/<label> for the active source revision")
    if if_match != store.publication_etag(job):
        return deny(412, "precondition",
                    "If-Match must equal the current publication_etag from "
                    "/preview/catalog/by-label/<label>")
    body = store.render_artifact_bytes(render)
    role = "target" if job["label"] == store.TARGET_LABEL else "decoy"
    store.observe({"event": "artifact_redeemed", "generation": gen, "role": role,
                   "render": render["render_id"],
                   "artifact_sha256": hashlib.sha256(body).hexdigest(), "ts": time.time()})
    resp = Response(body, status=200, mimetype=_fmt_mime(store.RESOURCE_FORMAT))
    resp.headers["Content-Length"] = str(len(body))
    resp.headers["ETag"] = store.publication_etag(job)
    return resp


def _fmt_mime(fmt):
    return {"pdf": "application/pdf", "csv": "text/csv",
            "json": "application/json"}.get((fmt or "").lower(), "application/octet-stream")


def register(bp):
    bp.add_url_rule("/preview/catalog", view_func=export_catalog)
    bp.add_url_rule("/preview/catalog/by-label/<label>", view_func=export_catalog_by_label)
    bp.add_url_rule("/preview/jobs/<job_id>/manifest/<render_id>", view_func=export_manifest)
    bp.add_url_rule("/preview/jobs/<job_id>/status/<render_id>", view_func=export_status)
    bp.add_url_rule(
        "/preview/jobs/<job_id>/authorizations/<render_id>/<epoch>/<purpose>",
        view_func=export_authority)
    bp.add_url_rule("/preview/artifacts/<artifact_ref>", view_func=export_artifact)
