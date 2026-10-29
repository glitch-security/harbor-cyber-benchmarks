"""Launch the hosted ledger application on its HTTP service port.

The application object is the Django WSGI callable wrapped by the deployment's
request-integrity gate (see wsgi.py).  The HTTP server is used unmodified; the
only addition is a timing-observation subclass of its connection object,
configured here before the server is created.
"""
from __future__ import annotations

import os
import sys

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "deployment.settings")

HOST = os.environ.get("LEDGER_HOST", "127.0.0.1")
PORT = int(os.environ.get("LEDGER_PORT", "9090"))
LOOKAHEAD = int(os.environ.get("LEDGER_LOOKAHEAD", "5"))
THREADS = int(os.environ.get("LEDGER_THREADS", "2"))


def main() -> int:
    import waitress.server as waitress_server

    from deployment.instrumented_channel import ScheduledChannel

    waitress_server.TcpWSGIServer.channel_class = ScheduledChannel

    from deployment.wsgi import application

    server = waitress_server.create_server(
        application,
        host=HOST,
        port=PORT,
        channel_request_lookahead=LOOKAHEAD,
        threads=THREADS,
        ident="Ledger Service",
        expose_tracebacks=False,
        clear_untrusted_proxy_headers=True,
    )
    print(f"ledger service listening on {HOST}:{server.effective_port}", flush=True)
    try:
        server.run()
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
