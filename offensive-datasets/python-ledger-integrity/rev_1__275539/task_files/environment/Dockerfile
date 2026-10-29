# ── MAIN image (agent phase + shared verifier) ─────────────────────────────────
# Contains agent-facing tooling, the proof-format document, writable task
# outputs and build-time verifier dependencies. Application and server source
# live only in the sealed target image.
FROM python:3.12-slim-bookworm@sha256:519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONNOUSERSITE=1 \
    TASK_AGENT_USER=auditor \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        bash ca-certificates curl git jq procps psmisc tmux util-linux vim-tiny \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install --no-cache-dir --retries 8 --timeout 120 \
        pytest==8.3.3 \
        'harbor-rewardkit==0.2.3' \
    && command -v rewardkit >/dev/null \
    && python3 --version \
    && tmux -V

RUN useradd --create-home --uid 10001 --shell /bin/bash auditor \
    && mkdir -p /app/output /testbed /logs/verifier /logs/artifacts /agent /tests /solution /scripts \
    && chown -R auditor:auditor /app/output /testbed /logs/artifacts /agent \
    && chown -R root:root /logs/verifier /tests /solution /scripts \
    && chmod 0700 /logs/verifier /tests /scripts \
    && chmod 0711 /solution

COPY main-entrypoint.sh /usr/local/bin/main-entrypoint.sh
RUN chmod 0555 /usr/local/bin/main-entrypoint.sh

# The proof grammar is public; no application or HTTP-server source is copied.
COPY proof-format.md /testbed/proof-format.md
RUN chown root:root /testbed/proof-format.md \
    && chmod 0444 /testbed/proof-format.md

WORKDIR /testbed
ENTRYPOINT ["/usr/local/bin/main-entrypoint.sh"]
CMD ["sleep", "infinity"]
