# Preview-export retrieval validation — process record

## Objective
Retrieve the target private export's fresh, currently-published rendered artifact
(`quarterly-energy-disclosure-2026` in the catalog) in the raw bytes of one of my
own gateway responses, reproducibly against freshly provisioned content under
whichever publication state is active.

## Discovery
- The portal has an asynchronous preview-export feature: a public catalog (with an
  exact-label lookup), per-render owner manifest/status, a per-render/epoch/purpose
  download-authority endpoint, and a grant-gated artifact endpoint.
- The target export has two authentic same-label renders with different public
  source revisions; the public catalog lookup reports which one is the currently
  approved publication and a fresh publication ETag. Approval can advance or roll
  back between fresh runs.
- My ordinary account administers only its own org. Another user's
  manifest/status/authority is refused to me directly; the artifact endpoint
  requires a correctly scoped grant AND the current publication precondition.

## Boundary
- Ordinary text and plain chunked previews are normalized, but the portal's
  compressed CSV export-preview path retains the upstream transfer header after the
  fetch client consumes both the chunked transfer coding and the gzip content
  coding. A linked CSV resource whose origin serves a gzip-coded body (inside valid
  outer chunk framing) that decodes to an over-long inner chunk survives
  reconstruction: the preview re-emits the decoded bytes under a chunked transfer
  header and the shared preview connection over-reads the responses that follow on
  the same upstream socket, sweeping the owner's concurrent manifest/status/authority
  polls into my own capture.
- Obtaining those records is necessary but not sufficient. The current-export
  endpoint serves the artifact only for the render that is the currently approved
  publication (identified by the public catalog's active source revision) and only
  when I present that catalog's fresh publication ETag as If-Match — in addition to
  the matching render/epoch/original-artifact grant and its revision rules. A
  first-match same-label render, a non-approved render, or a render status_etag used
  as If-Match is rejected.

## Proof
- `proof.json` creates a fresh public dataset + linked resource, reads the public
  catalog lookup for the active source revision and publication ETag, over-reads the
  owner polls, selects the manifest for the active source revision, correlates its
  ready/authority to bind the grant, and redeems the artifact with that grant and
  the publication ETag. The verifier replays it under both a forward and a rollback
  approval snapshot on freshly minted content and checks the fresh approved artifact
  body appears in my captured bytes each time. No artifact, grant, revision, source
  revision, publication ETag, route, or session value is hard-coded.
