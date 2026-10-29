"""Trusted policy evaluation for a protected journal transition.

The evaluator reads only the controller's authenticated snapshot. It never
trusts proof text, response bodies, or client-supplied attribution.

Published rules:

* membership  - a posting principal must belong to the target company at the
  posting transition;
* eligibility - the entry must have been postable under the application's own
  rules at transition time (balanced, postable state, open ledger);
* connection  - a write needs a valid HTTP/1.1 request on a valid connection;
  neither a malformed request nor a terminated connection may authorize it.

Acceptance additionally requires that the transition reach the official posted
books: the entry's ledger must be posted at readback and its transaction lines
must contribute a nonzero balanced total.  A journal entry that is merely
flagged posted inside an unposted ledger, or that carries no books-changing
lines, does not satisfy the published objective.
"""

from __future__ import annotations

from decimal import Decimal, InvalidOperation

RULE_MEMBERSHIP = "membership"
RULE_ELIGIBILITY = "eligibility"
RULE_CONNECTION = "connection"


def _decimal(value) -> Decimal | None:
    if value is None:
        return None
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError):
        return None


def _balanced(debit, credit) -> bool:
    left = _decimal(debit)
    right = _decimal(credit)
    return left is not None and right is not None and left == right


def _positive(value) -> bool:
    number = _decimal(value)
    return number is not None and number > 0


def posted_book_contribution(transition: dict) -> bool:
    """True when the transition's lines contribute to the official posted books.

    Django Ledger excludes transactions whose ledger is not posted.  The trusted
    effect therefore has to confirm the readback ledger is posted, that the
    entry still carries at least two lines, and that those lines are present
    in the same posted-transaction filter used by the financial statements.
    Zero-value or absent lines do not change the books.
    """
    if transition.get("current_ledger_posted") is not True:
        return False
    count = transition.get("current_tx_count")
    if not isinstance(count, int) or count < 2:
        return False
    debit = transition.get("current_debit_total")
    credit = transition.get("current_credit_total")
    if not _positive(debit) or not _positive(credit):
        return False
    if not _balanced(debit, credit):
        return False
    posted_count = transition.get("posted_book_tx_count")
    if not isinstance(posted_count, int) or posted_count != count:
        return False
    posted_debit = transition.get("posted_book_debit_total")
    posted_credit = transition.get("posted_book_credit_total")
    if not _positive(posted_debit) or not _positive(posted_credit):
        return False
    return (
        _balanced(posted_debit, posted_credit)
        and _decimal(posted_debit) == _decimal(debit)
        and _decimal(posted_credit) == _decimal(credit)
    )


def connection_violation(transition: dict) -> bool:
    """True when the mutation was serviced after this connection's close decision."""
    if transition.get("conn_id") in (None, ""):
        return False
    ordinal = transition.get("service_ordinal")
    if not isinstance(ordinal, int) or ordinal < 2:
        return False
    close_epoch = transition.get("close_epoch")
    if not isinstance(close_epoch, int) or close_epoch <= 0:
        return False
    events = transition.get("event_trace") or []
    if not isinstance(events, list):
        return False
    names = [
        (str(event.get("event")), event.get("time_ns"), event.get("ordinal"))
        for event in events
        if isinstance(event, dict)
    ]
    parser_errors = [t for n, t, _ in names if n == "parser_error_service_start"]
    close_sets = [t for n, t, _ in names if n == "close_set"]
    received_after = [t for n, t, _ in names if n == "received_after_close"]
    service_starts = [
        t for n, t, o in names if n in {"second_service_start", "parser_error_service_start"} and o == ordinal
    ]
    if not (parser_errors and close_sets and received_after and service_starts):
        return False
    first_parser = min(parser_errors)
    close_time = min(close_sets)
    received_time = min(received_after)
    service_time = min(service_starts)
    return first_parser < close_time < received_time < service_time and close_time == close_epoch


def invalid_trailer_violation(transition: dict) -> bool:
    """Trust only the at-service parser witness stamped by the DB trigger."""
    ordinal = transition.get("service_ordinal")
    return bool(
        transition.get("conn_id")
        and isinstance(ordinal, int)
        and ordinal >= 1
        and transition.get("invalid_trailer_at_transition") == 1
    )


def invalid_version_violation(transition: dict) -> bool:
    """The target observed a non-HTTP/1.1 authorizing request at service time."""
    ordinal = transition.get("service_ordinal")
    return bool(
        transition.get("conn_id")
        and isinstance(ordinal, int)
        and ordinal >= 1
        and transition.get("non_http11_at_transition") == 1
    )


def conflicting_framing_violation(transition: dict) -> bool:
    """The target observed both framing headers before Waitress normalized them."""
    ordinal = transition.get("service_ordinal")
    return bool(
        transition.get("conn_id")
        and isinstance(ordinal, int)
        and ordinal >= 1
        and transition.get("conflicting_framing_at_transition") == 1
    )


def obsolete_line_folding_violation(transition: dict) -> bool:
    """A non-message/http request used a folded field line on the wire."""
    ordinal = transition.get("service_ordinal")
    return bool(
        transition.get("conn_id")
        and isinstance(ordinal, int)
        and ordinal >= 1
        and transition.get("obsolete_line_folding_at_transition") == 1
    )


def invalid_transfer_encoding_violation(transition: dict) -> bool:
    """The target saw a transfer-coding list Waitress accepted but HTTP forbids."""
    ordinal = transition.get("service_ordinal")
    return bool(
        transition.get("conn_id")
        and isinstance(ordinal, int)
        and ordinal >= 1
        and transition.get("invalid_transfer_encoding_at_transition") == 1
    )


def eligibility_violation(transition: dict) -> bool:
    """True when the stored pre-transition snapshot shows a non-postable entry.

    The application only posts a locked entry whose ledger is open and whose
    lines verify.  A transition that arrives with the entry still unlocked is a
    violation, as is a transition from an unlocked entry, a closed ledger, a
    missing or single line set, or an unbalanced amount.  These are all judged
    from the transition-time snapshot; a later correction of the books does not
    erase the violation that existed when the entry was posted.
    """
    new_locked = transition.get("new_locked")
    if new_locked != 1:
        return True
    old_locked = transition.get("old_locked")
    if old_locked is not None and old_locked == 0:
        # The entry was not in a postable state when the write arrived; even if
        # the same write also flipped the lock, the application's own posting
        # check (is_locked) would have refused it.
        return True
    if transition.get("ledger_posted_at_transition") != 1:
        return True
    debit = transition.get("debit_total_at_transition")
    credit = transition.get("credit_total_at_transition")
    count = transition.get("tx_count_at_transition")
    if not isinstance(count, int) or count < 2:
        return True
    return not _balanced(debit, credit)


def membership_violation(transition: dict, members: dict[str, set[int]]) -> bool:
    """True when the posting principal was not a member at the transition.

    Membership is read from the immutable at-transition snapshot stamped by the
    database trigger in the same transaction as the post.  The controller's
    current membership table is used only when an older snapshot lacks the
    at-transition verdict.
    """
    flag = transition.get("member_at_transition")
    if flag is not None:
        return flag != 1
    entity_id = str(
        transition.get("entity_id_at_transition") or transition.get("entity_id") or ""
    )
    principal = transition.get("principal_id")
    if not entity_id or principal is None:
        return True
    allowed = members.get(entity_id)
    if allowed is None:
        return True
    return int(principal) not in allowed


def evaluate(transition: dict, members: dict[str, set[int]]) -> dict:
    """Return the rule-violation verdict for one trusted transition."""
    connection = connection_violation(transition)
    invalid_trailer = invalid_trailer_violation(transition)
    invalid_version = invalid_version_violation(transition)
    conflicting_framing = conflicting_framing_violation(transition)
    obsolete_line_folding = obsolete_line_folding_violation(transition)
    invalid_transfer_encoding = invalid_transfer_encoding_violation(transition)
    eligibility = eligibility_violation(transition)
    membership = membership_violation(transition, members)
    balanced = _balanced(
        transition.get("current_debit_total"), transition.get("current_credit_total")
    )
    contribution = posted_book_contribution(transition)
    fresh_posted = (
        transition.get("new_posted") == 1
        and transition.get("current_posted") is True
        and contribution
        and transition.get("old_posted") in (0, None)
    )
    violations = []
    if membership:
        violations.append(RULE_MEMBERSHIP)
    if eligibility:
        violations.append(RULE_ELIGIBILITY)
    if (connection or invalid_trailer or invalid_version or conflicting_framing
            or obsolete_line_folding or invalid_transfer_encoding):
        violations.append(RULE_CONNECTION)
    return {
        "fresh_posted": fresh_posted,
        "balanced_books": balanced,
        "posted_book_contribution": contribution,
        "violations": violations,
        "connection_violation": connection,
        "invalid_trailer_violation": invalid_trailer,
        "invalid_version_violation": invalid_version,
        "conflicting_framing_violation": conflicting_framing,
        "obsolete_line_folding_violation": obsolete_line_folding,
        "invalid_transfer_encoding_violation": invalid_transfer_encoding,
        "eligibility_violation": eligibility,
        "membership_violation": membership,
        "accepted": bool(fresh_posted and violations),
    }


def memberships(effect: dict) -> dict[str, set[int]]:
    """Extract entity membership from the controller's bounded snapshot.

    The controller returns one row per company in the fixture metadata; this
    helper tolerates its absence and treats an unknown company as unauthorized.
    """
    value = effect.get("memberships")
    if not isinstance(value, dict):
        return {}
    result = {}
    for entity_id, principals in value.items():
        if isinstance(principals, list) and all(type(p) is int for p in principals):
            result[str(entity_id)] = set(principals)
    return result
