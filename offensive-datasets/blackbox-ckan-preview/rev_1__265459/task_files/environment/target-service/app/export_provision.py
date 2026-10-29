# encoding: utf-8
"""Provision the per-generation private preview-export jobs (target + decoy) —
Revision C0: active-publication binding.

Runs at first boot and on every reset (as the ckan user). Mints the target export
with two authentic same-label renders (release_A / release_B) and assigns the
**currently approved publication** for this generation: approval alternates by
generation parity (one generation approves release_B, the next re-approves
release_A), so the verifier's two consecutive fresh replays exercise a forward and
a rollback snapshot in an order fixed before any proof is read. A fresh
publication_etag is minted each generation. The scoring hash derives from the
APPROVED render, never a fixed revision.

Writes the sidecar-private job store, the verifier-owned approved-render hash, and
the owner poll plan the independent actor replays (manifest + status + every scoped
authority for every render of every job). It never writes a passing receipt and
never exposes a grant, artifact byte, or the publication_etag outside the store /
the public catalog endpoint.
"""
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import export_store as store


def _read(path, default=""):
    try:
        with open(path) as fh:
            return fh.read().strip()
    except OSError:
        return default


def _atomic_write(path, text):
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        fh.write(text)
    os.replace(tmp, path)


def _poll_paths(jobs):
    """Every owner-visible read for every render of every job: manifest, status, and
    each scoped download authority. The public catalog/by-label lookup is NOT polled
    (it is public; the attacker reads it directly)."""
    paths = []
    for jid, job in jobs.items():
        for rid, render in job["renders"].items():
            paths.append("/preview/jobs/%s/manifest/%s" % (jid, rid))
            paths.append("/preview/jobs/%s/status/%s" % (jid, rid))
            for a in render["authorizations"]:
                paths.append("/preview/jobs/%s/authorizations/%s/%s/%s"
                             % (jid, rid, a["epoch"], a["purpose"]))
    return paths


def main():
    gen = int(_read(os.path.join(store.STATE, "generation"), "0") or 0)
    vic_token = _read(os.path.join(store.STATE, "vic_token"))

    target = store.mint_target_job(store.VICTIM_USER)
    # Active-publication snapshot by generation parity: forward (approve release_B)
    # on even generations, rollback (re-approve release_A) on odd. Deterministic and
    # independent of any submitted proof.
    want = "release_B" if gen % 2 == 0 else "release_A"
    approved_rid = next(rid for rid, r in target["renders"].items() if r["release"] == want)
    store.set_publication(target, approved_rid)

    decoy = store.mint_decoy_job(store.VICTIM_USER, store.DECOY_LABEL,
                                 store.DECOY_PUBLIC_ID, store.DECOY_SRCREV)
    jobs = {target["job_id"]: target, decoy["job_id"]: decoy}

    data = {
        "generation": gen,
        "victim_user": store.VICTIM_USER,
        "victim_token_sha": hashlib.sha256(vic_token.encode()).hexdigest() if vic_token else "",
        "jobs": jobs,
    }
    store.save_store(data)
    # verifier-owned: the fresh APPROVED-render artifact hash for this generation.
    _atomic_write(store.VERIFIER_HASH, store.target_artifact_sha256(target))
    _atomic_write(os.path.join(store.STATE, "export_target.json"),
                  json.dumps({"target_job": target["job_id"],
                              "approved_release": want,
                              "target_artifact_ref": store.approved_render(target)["artifact_ref"],
                              "target_label": store.TARGET_LABEL,
                              "poll_paths": _poll_paths(jobs)}))
    print("provisioned exports gen=%d approved=%s target_job=%s poll_paths=%d"
          % (gen, want, target["job_id"], len(_poll_paths(jobs))))


if __name__ == "__main__":
    main()
