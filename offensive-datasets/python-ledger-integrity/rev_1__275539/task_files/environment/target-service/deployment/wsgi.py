"""WSGI entry point for the hosted ledger installation.

The Django callable is wrapped by a narrow request-integrity gate.  Known
invalid single-request wire forms that the HTTP server has already observed
for the request being dispatched are refused here, before Django routing, so
an invalid authorizing message cannot reach an application write.  The gate
reads only request-local observations -- malformed chunk trailer, non-HTTP/1.1
version, conflicting framing, obsolete line folding, and forbidden transfer
coding.  It deliberately inspects no connection lifecycle state (close
decisions, service ordinals, or pending closure): a well-formed request that
reaches this boundary is dispatched on its own merits even when its
connection is already closing.
"""
import os

from django.core.wsgi import get_wsgi_application

from deployment import audit_context

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "deployment.settings")

_django_application = get_wsgi_application()

INVALID_WIRE = (
    "invalid_trailer",
    "non_http11",
    "conflicting_framing",
    "obsolete_line_folding",
    "invalid_transfer_encoding",
)


def application(environ, start_response):
    observed = audit_context.snapshot()
    if any(observed[name] for name in INVALID_WIRE):
        start_response("400 Bad Request", [("Content-Length", "0")])
        return [b""]
    return _django_application(environ, start_response)
