# ── TARGET-SERVICE image (sealed appliance) ────────────────────────────────────
# Owns the authentic application, private deployment state, the audit-bearing
# database, the timing-observation channel, and the narrow controller. Nothing
# in this image is copied into the main agent image.
FROM python:3.12-slim-bookworm@sha256:519591d6871b7bc437060736b9f7456b8731f1499a57e22e6c285135ae657bf7

ARG TASK_AGENT_UID=10001
ARG TASK_SERVICE_UID=10002

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONNOUSERSITE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SVC_PORT=9090 \
    SVC_ROOT=/opt/ledger \
    SVC_STATE_DIR=/var/lib/ledger \
    SVC_LOG=/var/log/ledger/app.log \
    SVC_PYTHON=/opt/ledger-venv/bin/python \
    SVC_USER=ledger \
    LEDGER_STATE_DIR=/var/lib/ledger \
    LEDGER_STATIC_ROOT=/opt/ledger-static \
    LEDGER_EVENT_LOG=/var/lib/ledger/events.jsonl \
    TARGET_CONTROL_PORT=19999 \
    TARGET_HEALTH_URL=http://127.0.0.1:9090/auth/login/ \
    TARGET_START_SCRIPT=/usr/local/bin/start-app.sh \
    TARGET_RESET_SCRIPT=/usr/local/bin/control-reset.sh \
    TARGET_RESTART_SCRIPT=/usr/local/bin/control-restart.sh \
    TARGET_DB_PATH=/var/lib/ledger/state.sqlite3 \
    TARGET_FIXTURE_PATH=/var/lib/ledger/fixture.json \
    TARGET_EVENT_LOG=/var/lib/ledger/events.jsonl \
    TARGET_MANIFEST=/opt/target-manifest.txt

RUN apt-get update && apt-get install -y --no-install-recommends \
        bash ca-certificates curl procps psmisc util-linux \
    && rm -rf /var/lib/apt/lists/*

RUN command -v runuser >/dev/null \
    && useradd --create-home --uid "${TASK_AGENT_UID}" --shell /bin/bash auditor \
    && useradd --no-create-home --uid "${TASK_SERVICE_UID}" --shell /usr/sbin/nologin ledger \
    && mkdir -p /opt/ledger /opt/ledger/vendor /opt/ledger-static /var/lib/ledger /var/log/ledger \
        /testbed /logs /logs/verifier /app/output /tests /solution /scripts /var/run \
    && chown -R root:root /opt/ledger /opt/ledger-static /var/lib/ledger /var/log/ledger /tests /solution /scripts /logs/verifier \
    && chown -R auditor:auditor /testbed /app/output \
    && chmod 0700 /var/lib/ledger /var/log/ledger /tests /solution /scripts /logs/verifier

# ── Runtime dependencies, installed at build time only. ───────────────────────
COPY requirements.lock /opt/ledger/requirements.lock
RUN python3 -m venv /opt/ledger-venv \
    && /opt/ledger-venv/bin/pip install --no-cache-dir --require-hashes -r /opt/ledger/requirements.lock \
    && /opt/ledger-venv/bin/python -c "import django, sys; print(django.get_version(), sys.version)"

# ── Authentic application source, deployment integration and pinned server. ───
# Build-context directories are named without third-party bundle markers, while
# the sealed runtime paths stay the authentic `/opt/ledger/vendor/...`.
COPY runtime-libs/django-ledger /opt/ledger/vendor/django-ledger
COPY runtime-libs/waitress /opt/ledger/vendor/waitress
COPY deployment /opt/ledger/deployment
COPY appliance /opt/ledger/appliance
COPY static /opt/ledger-static
COPY admin-css-assets /opt/ledger-static/admin/css/vendor
COPY admin-js-assets /opt/ledger-static/admin/js/vendor

RUN /opt/ledger-venv/bin/python -m compileall -q /opt/ledger/deployment \
    && /opt/ledger-venv/bin/python -c "import sys; sys.path[:0]=['/opt/ledger/vendor/django-ledger','/opt/ledger/vendor/waitress']; import django_ledger, waitress; print(django_ledger.__version__, waitress.__version__ if hasattr(waitress,'__version__') else 'ok')"

# ── Launcher, controller and lifecycle scripts. ───────────────────────────────
COPY start-app.sh control-reset.sh control-restart.sh healthcheck entrypoint.sh /usr/local/bin/
COPY target-warden.py /usr/local/lib/target-warden.py
RUN chmod 0555 /usr/local/bin/start-app.sh /usr/local/bin/control-reset.sh \
        /usr/local/bin/control-restart.sh /usr/local/bin/healthcheck /usr/local/bin/entrypoint.sh \
    && chmod 0555 /usr/local/lib/target-warden.py \
    && chmod 0555 /opt/ledger/appliance \
    && chown root:root /usr/local/bin/start-app.sh /usr/local/bin/control-reset.sh \
        /usr/local/bin/control-restart.sh /usr/local/bin/healthcheck /usr/local/bin/entrypoint.sh \
        /usr/local/lib/target-warden.py

# ── Sealed-runtime manifest. Covers every file whose change could forge a pass. ─
RUN sha256sum \
        /opt/ledger/appliance \
        /opt/ledger/deployment/settings.py \
        /opt/ledger/deployment/urls.py \
        /opt/ledger/deployment/wsgi.py \
        /opt/ledger/deployment/run_service.py \
        /opt/ledger/deployment/seed.py \
        /opt/ledger/deployment/bootstrap.py \
        /opt/ledger/deployment/instrumented_channel.py \
        /opt/ledger/deployment/audit_context.py \
        /opt/ledger/deployment/audit_middleware.py \
        /opt/ledger/deployment/views.py \
        /opt/ledger/deployment/templates/deployment/work.html \
        /opt/ledger/vendor/django-ledger/django_ledger/models/journal_entry.py \
        /usr/local/bin/start-app.sh \
        /usr/local/bin/control-reset.sh \
        /usr/local/bin/control-restart.sh \
        /usr/local/lib/target-warden.py \
    | sort > /opt/target-manifest.txt \
    && chmod 0444 /opt/target-manifest.txt

# ── Private control key: identical bytes staged for the trusted verifier only. ─
COPY control-auth.key /run/secrets/control-auth.key
RUN chmod 0400 /run/secrets/control-auth.key && chown root:root /run/secrets/control-auth.key

WORKDIR /testbed
HEALTHCHECK --interval=3s --timeout=4s --retries=20 --start-period=20s CMD ["/usr/local/bin/healthcheck"]
ENTRYPOINT ["python3", "/usr/local/lib/target-warden.py"]
CMD ["sleep", "infinity"]
