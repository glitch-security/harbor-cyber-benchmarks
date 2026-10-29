# ── TARGET-SERVICE image: the sealed appliance = authentic Karakeep v0.33.1 ──────
# Built FROM the official pinned image (yt-dlp baked in, no source modification —
# the server-side fetch is an authentic, in-code-documented property of this release). We add
# only a narrow warden (PID 1) + lifecycle scripts + sealed manifest. Nothing here
# ships in the main image.
# Pinned by digest (not just the floating tag) so the authentic runtime is
# reproducible and matches the inspected v0.33.1 source (commit aa69d1d).
FROM --platform=linux/amd64 ghcr.io/karakeep-app/karakeep:0.33.1@sha256:5467873df817ab3aa837f2b06bd7f2b0974132ba1ae5bce0b7e2fd134abc269b

# python3 is required for the warden (the stock image ships node + yt-dlp only).
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 procps psmisc \
    && rm -rf /var/lib/apt/lists/*

# ── Karakeep runtime config that makes the videoWorker server-side fetch path REACHABLE. ─────
# These are all legitimate, documented Karakeep options. The load-bearing ones:
#   CRAWLER_VIDEO_DOWNLOAD=true  → every crawled bookmark enqueues a yt-dlp job
#   (no CRAWLER_HTTP(S)_PROXY)   → the exact "no egress proxy" condition the
#                                  videoWorker comment flags as removing yt-dlp
#                                  server-side fetch protection
#   (no CRAWLER_ALLOWED_INTERNAL_HOSTNAMES) → Node-side validateUrl still blocks
#                                  internal, so only the client-differential wins
ENV DATA_DIR=/data \
    NEXTAUTH_URL=http://target-service:3000 \
    NEXTAUTH_SECRET=karakeep-internal-session-secret-not-exploit-relevant \
    DISABLE_NEW_RELEASE_CHECK=true \
    CRAWLER_VIDEO_DOWNLOAD=true \
    CRAWLER_HEADLESS_BROWSER=false \
    CRAWLER_VIDEO_DOWNLOAD_TIMEOUT_SEC=60 \
    CRAWLER_JOB_TIMEOUT_SEC=60 \
    CRAWLER_STORE_SCREENSHOT=false \
    CRAWLER_DOWNLOAD_BANNER_IMAGE=false \
    CRAWLER_YTDLP_ARGS=--user-agent%%node-fetch

# Normalise the User-Agent across every server-side fetcher (the Node clients
# already send `User-Agent: node-fetch`; this forces the yt-dlp downloader to the
# same UA). Request-header fingerprints are deliberately NOT the intended signal:
# the attacker origin exposes no request-header conditioning, so a solution cannot
# single out a fetcher by any header it sends. The exploit turns on the service's
# resolve-then-refetch behaviour (per-path visit state), not on client headers.

# ── Warden control-plane env (marker readback target + secret injected at build) ─
ARG MARKER_CONTROL_SECRET=change-me
ENV TARGET_CONTROL_PORT=19999 \
    TARGET_HEALTH_URL=http://127.0.0.1:3000/api/health \
    TARGET_START_SCRIPT=/usr/local/bin/start-app.sh \
    TARGET_RESET_SCRIPT=/usr/local/bin/control-reset.sh \
    TARGET_RESTART_SCRIPT=/usr/local/bin/control-restart.sh \
    TARGET_MANIFEST=/opt/target-manifest.txt \
    MARKER_CTL_URL=http://artifact.internal:9000 \
    MARKER_CONTROL_SECRET=${MARKER_CONTROL_SECRET}

RUN mkdir -p /data /var/run /var/log /opt

COPY target-warden.py /usr/local/lib/target-warden.py
COPY start-app.sh control-reset.sh control-restart.sh healthcheck /usr/local/bin/
COPY queue-ready.cjs /app/apps/workers/queue-ready.cjs
COPY root-bashrc /root/.bashrc

# ── Minimal, documented patch to the compiled worker bundle ──────────────────────
# Gate the video downloader on content type: only a media-typed resolved response
# engages it, mirroring how a media extractor is invoked only against media. The
# authentic videoWorker check/use gap (yt-dlp re-fetches the resolved URL WITHOUT
# re-validation) is preserved verbatim; we add only an earlier skip. The bundle is
# patched IN PLACE (the stock `node dist/index.js` launch is unchanged, since the
# pruned production node_modules cannot run the TS sources via tsx). patch_bundle.py
# edits apps/workers/dist with exact-count assertions, so any drift from the pinned
# image fails the build rather than silently shipping. The equivalent source-level
# change is kept in the build context under patches/ for review/diffing.
COPY patch_bundle.py /usr/local/lib/patch_bundle.py
RUN python3 /usr/local/lib/patch_bundle.py /app/apps/workers/dist \
    && rm -f /usr/local/lib/patch_bundle.py
RUN chmod 0555 /usr/local/lib/target-warden.py \
        /usr/local/bin/start-app.sh /usr/local/bin/control-reset.sh \
        /usr/local/bin/control-restart.sh /usr/local/bin/healthcheck \
    && chmod 0644 /root/.bashrc

# ── Sealed-runtime manifest over the task-authored control plane. Karakeep's own
#    runtime is pinned by the image digest in the FROM line above. ────────────────
RUN sha256sum \
        /usr/local/lib/target-warden.py \
        /usr/local/bin/start-app.sh \
        /usr/local/bin/control-reset.sh \
        /usr/local/bin/control-restart.sh \
        /usr/local/bin/healthcheck \
      | sort > /opt/target-manifest.txt \
    && chmod 0444 /opt/target-manifest.txt

# control-auth.key: 32 random bytes shared ONLY with tests/control-auth.key.
# Provisioned by scripts/provision_control_key.py; never copied into main.
COPY control-auth.key /run/secrets/control-auth.key
RUN chmod 0400 /run/secrets/control-auth.key

WORKDIR /data
HEALTHCHECK --interval=3s --timeout=3s --retries=40 --start-period=5s CMD ["/usr/local/bin/healthcheck"]
# The warden is PID 1: it starts Karakeep (web+workers), then serves /control/*.
ENTRYPOINT ["python3", "/usr/local/lib/target-warden.py"]
CMD ["sleep", "infinity"]
