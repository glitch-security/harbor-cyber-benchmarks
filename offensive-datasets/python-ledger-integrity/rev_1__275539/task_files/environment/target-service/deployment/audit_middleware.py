"""Read-only request middleware that records the resolved principal.

Runs after Django's AuthenticationMiddleware.  It never changes
authorization, the response, or request handling; it only copies the resolved
user id into the worker-thread context used by the private audit triggers.
"""
from __future__ import annotations

from django.db import connection
from django.db.backends.signals import connection_created
from django.dispatch import receiver

from deployment import audit_context


@receiver(connection_created)
def _register_context_functions(sender, connection, **kwargs):  # noqa: ARG001
    audit_context.install_sqlite_functions(connection)


def _install_on_existing():
    try:
        if connection.connection is not None:
            audit_context.install_sqlite_functions(connection)
    except Exception:
        pass


class RequestPrincipalMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        _install_on_existing()

    def __call__(self, request):
        _install_on_existing()
        try:
            user = getattr(request, "user", None)
            if user is not None and getattr(user, "is_authenticated", False):
                audit_context.set_principal(int(user.pk))
        except Exception:
            pass
        return self.get_response(request)
