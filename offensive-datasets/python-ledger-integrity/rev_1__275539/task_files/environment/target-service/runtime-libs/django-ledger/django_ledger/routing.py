from contextvars import ContextVar
from contextlib import contextmanager

from django_ledger.settings import DJANGO_LEDGER_DB_ROUTER_HINT_KEY, DJANGO_LEDGER_DB_ROUTING_ALIAS

DJL_DB_ROUTING_CONTEXT = ContextVar(DJANGO_LEDGER_DB_ROUTER_HINT_KEY, default=DJANGO_LEDGER_DB_ROUTING_ALIAS)

# list of db actions...
DJL_DB_ROUTING_ACTION_COA_CONFIGURE = 'coa_configure'


DJL_DB_ROUTING_ACTIONS = frozenset({DJL_DB_ROUTING_ACTION_COA_CONFIGURE})


@contextmanager
def db_routing_action(action):
    """Bind a router action for the current task.

    Parameters
    ----------
    action : str
        Router action name.
    """
    token = DJL_DB_ROUTING_CONTEXT.set(action)
    try:
        yield
    finally:
        DJL_DB_ROUTING_CONTEXT.reset(token)
