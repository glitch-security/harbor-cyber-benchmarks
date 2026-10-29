#!/usr/bin/env python3
"""Build-time patch of the compiled Karakeep worker bundle (apps/workers/dist).

Adds a content-type gate in front of the video downloader: the downloader only
engages when the resolved response presents as media (video/audio/HLS/DASH),
mirroring how a media extractor is invoked only against a media resource. The
authentic videoWorker check/use gap is preserved verbatim — yt-dlp still
re-fetches the resolved URL WITHOUT re-validation; we only add an earlier skip.

Two edits (exact-count asserted; the build fails on any drift from the pinned
image, so a silent mismatch can never ship):

  (A) resolveValidatedRedirectUrl (in its chunk): additionally return the resolved
      response's content-type, captured from the GET it ALREADY performs (no extra
      request -> the resolve-then-refetch timing is unchanged).
  (B) the videoWorker call site (index.js): read that content-type and return
      early (skip the downloader) unless it is a media type.
"""
import glob
import os
import re
import sys

DIST = sys.argv[1] if len(sys.argv) > 1 else "/app/apps/workers/dist"


def patch_file(path, edits):
    with open(path, "r", encoding="utf-8") as f:
        s = f.read()
    for name, pat, repl, want in edits:
        s, n = re.subn(pat, lambda m, r=repl: r, s)
        if n != want:
            sys.exit(f"patch_bundle: {name!r}: expected {want} match(es), got {n} in {path}")
    with open(path, "w", encoding="utf-8") as f:
        f.write(s)


# (A) locate the chunk that defines resolveValidatedRedirectUrl
chunk = None
for p in sorted(glob.glob(os.path.join(DIST, "*.js"))):
    with open(p, "r", encoding="utf-8") as f:
        if "async function resolveValidatedRedirectUrl(" in f.read():
            chunk = p
            break
if chunk is None:
    sys.exit("patch_bundle: could not locate the resolveValidatedRedirectUrl chunk")

patch_file(chunk, [
    ("resolve/non-redirect-return",
     r'if \(!isRedirectResponse\(response\)\)\s*\{\s*closeResponseBody\(response\);\s*return requestUrl;\s*\}',
     'if (!isRedirectResponse(response)) { const __ct = response.headers.get("content-type"); '
     'closeResponseBody(response); return { url: requestUrl, contentType: __ct }; }',
     1),
    ("resolve/no-location-return",
     r'if \(!locationHeader\)\s*return requestUrl;',
     'if (!locationHeader) return { url: requestUrl, contentType: null };',
     1),
])

# (B) the single videoWorker call site in index.js
INDEX = os.path.join(DIST, "index.js")
GATE = (
    'normalizedUrl = resolvedUrl.url.toString(); '
    'const __ct = (resolvedUrl.contentType || "").split(";")[0].trim().toLowerCase(); '
    'if (!(__ct.startsWith("video/") || __ct.startsWith("audio/") || '
    '__ct === "application/vnd.apple.mpegurl" || __ct === "application/x-mpegurl" || '
    '__ct === "application/dash+xml")) { return; }'
)
patch_file(INDEX, [
    ("videoWorker/content-gate",
     r'normalizedUrl = resolvedUrl\.toString\(\);',
     GATE,
     1),
])

print("patch_bundle: OK")
