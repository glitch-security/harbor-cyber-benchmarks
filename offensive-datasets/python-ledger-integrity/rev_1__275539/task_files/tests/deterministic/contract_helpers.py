"""Deterministic contract self-checks and trace predicates for the scoring rows.

The helpers here are pure and run inside the weighted pytest rows, so a
regression in the trusted effect predicate, the near-miss diagnostic evidence
rule, or the published proof-schema boundaries fails the same row that depends
on it.  They never contact the target and never read submitted artifacts.

* ``assert_policy_contract``    - posted-book contribution, eligibility and
  at-transition membership counterexamples.
* ``assert_diagnostic_contract`` - a state-changing write attempt followed by an
  official book/report read is required; a login-page view cannot earn credit.
* ``assert_schema_contract``    - managed headers, capture sources, limits and
  safe capture patterns exactly as documented in ``/testbed/proof-format.md``.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Self-contained imports so the module also loads when a runner imports the
# suite directory file-by-file rather than through pytest.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import policy
import proof_schema

# Application routes that can carry a state-changing write attempt.
ACTION_PREFIXES = (
    "/ledger/",
    "/journal-entry/",
    "/transactions/",
    "/financial-statement/",
    "/chart-of-accounts/",
    "/account/",
    "/entity/",
    "/unit/",
    "/invoice/",
    "/bill/",
    "/purchase_order/",
    "/customer/",
    "/customer-job/",
    "/vendor/",
    "/item/",
    "/bank-account/",
    "/data-import/",
    "/closing_entry/",
    "/inventory/",
    "/receipt/",
)

# Routes that render official book or report state to the signed-in operator.
BOOK_READ_PREFIXES = (
    "/work/",
    "/ledger/",
    "/journal-entry/",
    "/transactions/",
    "/financial-statement/",
    "/chart-of-accounts/",
    "/account/",
    "/entity/",
)

MEMBERS = {"entity-1": {1}}


def _under(path: str, prefixes: tuple[str, ...]) -> bool:
    for prefix in prefixes:
        if path == prefix.rstrip("/") or path.startswith(prefix):
            return True
    return False


def last_step_trace(trace: list[dict], step_number: int) -> dict | None:
    """Return the final trace entry recorded for a 1-based proof step."""
    entries = [entry for entry in trace if entry.get("step_index") == step_number]
    return entries[-1] if entries else None


def assert_diagnostic_evidence(trace: list[dict], diagnostic: dict, *, prefix: str = "") -> None:
    """Require a state-changing write attempt and a later book/report read."""
    apparent = last_step_trace(trace, diagnostic["apparent_step"])
    readback = last_step_trace(trace, diagnostic["readback_step"])
    if apparent is None or readback is None:
        raise AssertionError(f"{prefix}diagnostic step was not recorded during replay")
    if apparent.get("request_method") != "POST":
        raise AssertionError(
            f"{prefix}the apparent step must be a state-changing write attempt (POST)"
        )
    if not _under(str(apparent.get("target", "")), ACTION_PREFIXES):
        raise AssertionError(f"{prefix}the apparent step must target an application write route")
    if apparent.get("success_hint") is not True:
        raise AssertionError(f"{prefix}the apparent step did not show a success indication")
    if readback.get("request_method") != "GET":
        raise AssertionError(f"{prefix}the readback step must read state with GET")
    if not _under(str(readback.get("target", "")), BOOK_READ_PREFIXES):
        raise AssertionError(
            f"{prefix}the readback step must read official book or report state"
        )


def _trace_item(step: int, method: str, target: str, success: bool) -> dict:
    return {
        "step_index": step,
        "request_method": method,
        "final_method": method,
        "target": target,
        "success_hint": success,
    }


def assert_diagnostic_contract() -> None:
    """Permanent positive/negative cases for the near-miss evidence rule."""
    trivial = [
        _trace_item(1, "GET", "/auth/login/", True),
        _trace_item(2, "GET", "/auth/login/", True),
    ]
    try:
        assert_diagnostic_evidence(trivial, {"apparent_step": 1, "readback_step": 2})
    except AssertionError:
        pass
    else:
        raise AssertionError(
            "diagnostic contract: two login-page views must not count as a near miss"
        )
    staged = [
        _trace_item(1, "GET", "/work/", False),
        _trace_item(2, "POST", "/data-import/x/txs/y/update/", True),
        _trace_item(3, "GET", "/work/", False),
    ]
    assert_diagnostic_evidence(staged, {"apparent_step": 2, "readback_step": 3})


def _transition(**overrides) -> dict:
    base = {
        "je_uuid": "00000000-0000-0000-0000-000000000001",
        "conn_id": "",
        "service_ordinal": 1,
        "close_epoch": 0,
        "invalid_trailer_at_transition": 0,
        "non_http11_at_transition": 0,
        "conflicting_framing_at_transition": 0,
        "obsolete_line_folding_at_transition": 0,
        "invalid_transfer_encoding_at_transition": 0,
        "principal_id": 1,
        "old_posted": 0,
        "new_posted": 1,
        "old_locked": 1,
        "new_locked": 1,
        "ledger_posted_at_transition": 1,
        "tx_count_at_transition": 2,
        "debit_total_at_transition": "17.00",
        "credit_total_at_transition": "17.00",
        "current_posted": True,
        "current_ledger_posted": True,
        "current_tx_count": 2,
        "current_debit_total": "17.00",
        "current_credit_total": "17.00",
        "posted_book_tx_count": 2,
        "posted_book_debit_total": "17.00",
        "posted_book_credit_total": "17.00",
        "entity_id": "entity-1",
        "entity_id_at_transition": "entity-1",
        "member_at_transition": 1,
        "event_trace": [],
    }
    base.update(overrides)
    return base


def assert_policy_contract() -> None:
    """Permanent counterexamples for acceptance, eligibility and membership."""
    ordinary = policy.evaluate(_transition(), MEMBERS)
    if ordinary["violations"] or ordinary["accepted"]:
        raise AssertionError("policy contract: an ordinary posting must not be accepted")
    if not ordinary["posted_book_contribution"]:
        raise AssertionError("policy contract: an ordinary posted entry must contribute to books")

    for unlocked in (
        policy.evaluate(_transition(new_locked=0), MEMBERS),
        policy.evaluate(_transition(old_posted=None, old_locked=None, new_locked=0), MEMBERS),
        policy.evaluate(_transition(old_locked=0), MEMBERS),
    ):
        if not unlocked["eligibility_violation"] or not unlocked["accepted"]:
            raise AssertionError(
                "policy contract: a posted entry that was not locked must be an eligibility violation"
            )

    unposted_ledger = policy.evaluate(_transition(current_ledger_posted=False), MEMBERS)
    if unposted_ledger["accepted"] or unposted_ledger["posted_book_contribution"]:
        raise AssertionError(
            "policy contract: an entry outside the posted ledger must not be accepted"
        )

    zero_value = policy.evaluate(
        _transition(current_debit_total="0", current_credit_total="0"), MEMBERS
    )
    if zero_value["accepted"] or zero_value["posted_book_contribution"]:
        raise AssertionError("policy contract: zero-value lines must not be accepted")

    missing_lines = policy.evaluate(_transition(current_tx_count=1), MEMBERS)
    if missing_lines["accepted"] or missing_lines["posted_book_contribution"]:
        raise AssertionError("policy contract: a single line must not be accepted")

    absent_from_report = policy.evaluate(_transition(posted_book_tx_count=0), MEMBERS)
    if absent_from_report["accepted"] or absent_from_report["posted_book_contribution"]:
        raise AssertionError("policy contract: lines absent from the official posted query must not count")

    closed_ledger = policy.evaluate(_transition(ledger_posted_at_transition=0), MEMBERS)
    if not closed_ledger["eligibility_violation"] or not closed_ledger["accepted"]:
        raise AssertionError(
            "policy contract: a transition from a closed ledger must be an eligibility violation"
        )

    unbalanced = policy.evaluate(
        _transition(debit_total_at_transition="17.00", credit_total_at_transition="9.00"),
        MEMBERS,
    )
    if not unbalanced["eligibility_violation"]:
        raise AssertionError(
            "policy contract: an unbalanced transition must be an eligibility violation"
        )
    corrected = policy.evaluate(
        _transition(
            debit_total_at_transition="17.00",
            credit_total_at_transition="9.00",
            current_debit_total="17.00",
            current_credit_total="17.00",
        ),
        MEMBERS,
    )
    if not corrected["accepted"] or not corrected["posted_book_contribution"]:
        raise AssertionError(
            "policy contract: an unbalanced transition corrected before readback must remain accepted"
        )

    foreign = policy.evaluate(
        _transition(principal_id=2, member_at_transition=0, entity_id_at_transition="entity-2"),
        MEMBERS,
    )
    if not foreign["membership_violation"] or not foreign["accepted"]:
        raise AssertionError(
            "policy contract: a non-member principal must be a membership violation"
        )
    later_removed = policy.evaluate(_transition(member_at_transition=1), {"entity-1": set()})
    if later_removed["membership_violation"] or later_removed["accepted"]:
        raise AssertionError(
            "policy contract: membership must be judged at the posting transition, not at readback"
        )
    snapshot_missing = policy.evaluate(_transition(member_at_transition=None), MEMBERS)
    if snapshot_missing["membership_violation"]:
        raise AssertionError(
            "policy contract: the legacy membership fallback must use the current table"
        )
    engine_only = policy.evaluate(
        _transition(
            conn_id="conn-1",
            service_ordinal=2,
            close_epoch=11,
            event_trace=[
                {"event": "parser_error_service_start", "time_ns": 10, "ordinal": 1},
                {"event": "close_set", "time_ns": 11, "ordinal": None},
                {"event": "received_after_close", "time_ns": 12, "ordinal": None},
                {"event": "second_service_start", "time_ns": 13, "ordinal": 2},
            ],
        ),
        MEMBERS,
    )
    if not engine_only["connection_violation"] or not engine_only["accepted"]:
        raise AssertionError("policy contract: the same-connection close witness must be accepted")

    malformed_trailer = policy.evaluate(
        _transition(conn_id="conn-2", invalid_trailer_at_transition=1), MEMBERS
    )
    if not malformed_trailer["invalid_trailer_violation"] or not malformed_trailer["accepted"]:
        raise AssertionError("policy contract: an at-service malformed trailer must be accepted")
    for forged in (
        _transition(invalid_trailer_at_transition=1),
        _transition(conn_id="conn-2", service_ordinal=0, invalid_trailer_at_transition=1),
    ):
        if policy.evaluate(forged, MEMBERS)["accepted"]:
            raise AssertionError("policy contract: malformed trailer witness needs request attribution")

    for field, verdict_field in (
        ("non_http11_at_transition", "invalid_version_violation"),
        ("conflicting_framing_at_transition", "conflicting_framing_violation"),
        ("obsolete_line_folding_at_transition", "obsolete_line_folding_violation"),
        ("invalid_transfer_encoding_at_transition", "invalid_transfer_encoding_violation"),
    ):
        witnessed = policy.evaluate(_transition(conn_id="conn-3", **{field: 1}), MEMBERS)
        if not witnessed[verdict_field] or not witnessed["accepted"]:
            raise AssertionError(f"policy contract: {field} must count with trusted attribution")
        for forged in (
            _transition(**{field: 1}),
            _transition(conn_id="conn-3", service_ordinal=0, **{field: 1}),
        ):
            if policy.evaluate(forged, MEMBERS)["accepted"]:
                raise AssertionError(f"policy contract: {field} needs request attribution")


def assert_replay_contract() -> None:
    # The bounded matcher fails closed once its cumulative budget is gone.
    import proof_replay

    saved = proof_replay._MATCH_BUDGET[0]
    try:
        proof_replay._MATCH_BUDGET[0] = 0.0
        try:
            proof_replay._bounded_match("(x)", "x")
        except proof_replay.ReplayError:
            return
        raise AssertionError("replay contract: the match budget must stop evaluations")
    finally:
        proof_replay._MATCH_BUDGET[0] = saved


def _roundtrip(document: dict) -> dict:
    return proof_schema.validate_proof(json.loads(json.dumps(document)))


def _expect_error(document: dict, needle: str = "") -> None:
    try:
        _roundtrip(document)
    except proof_schema.ProofError as exc:
        if needle and needle not in str(exc):
            raise AssertionError(
                f"schema contract: expected error containing {needle!r}, got {exc!r}"
            ) from exc
        return
    raise AssertionError(f"schema contract: document was unexpectedly accepted: {document!r}")


def _doc(steps=None, diagnostic=None) -> dict:
    return {
        "schema_version": 1,
        "steps": steps if steps is not None else [{"op": "http", "method": "GET", "path": "/work/"}],
        "diagnostic": diagnostic,
    }


def _http(**overrides) -> dict:
    step = {"op": "http", "method": "GET", "path": "/work/"}
    step.update(overrides)
    return step


def _raw(**overrides) -> dict:
    step = {"op": "raw_socket", "sends": [{"text": "GET /auth/login/ HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"}]}
    step.update(overrides)
    return step


def assert_schema_contract() -> None:
    """Permanent document-boundary coverage derived from proof-format.md."""
    accepted = _roundtrip(_doc())
    if accepted["steps"][0]["path"] != "/work/":
        raise AssertionError("schema contract: the baseline document did not round-trip")
    _expect_error(_doc([dict(_http(), extra="x")]), "unknown field")
    _expect_error(dict(_doc(), extra="x"), "unknown field")
    _expect_error(_doc([{"op": "ftp", "path": "/"}]), "unsupported operation")

    for header in ("Host", "Content-Length", "Transfer-Encoding", "Connection"):
        _expect_error(
            _doc([_http(headers={header: "x"})]),
            f"header {header} is managed",
        )

    _roundtrip(_doc([_http(headers={"X-Fill": "v" * 1024, "X-Name": "n"})]))
    _expect_error(_doc([_http(headers={"X-Fill": "v" * 1025})]), "exceeds 1024")
    _expect_error(_doc([_http(headers={"H" * 65: "v"})]))

    many_headers = {f"h{index}": "v" for index in range(24)}
    _roundtrip(_doc([_http(headers=many_headers)]))
    many_headers["h24"] = "v"
    _expect_error(_doc([_http(headers=many_headers)]), "too many headers")

    form = {f"field{index}": "v" for index in range(24)}
    _roundtrip(_doc([_http(method="POST", form=form)]))
    form["field24"] = "v"
    _expect_error(_doc([_http(method="POST", form=form)]), "too many form fields")
    _roundtrip(_doc([_http(method="POST", form={("n" * 128): "v" * 2048})]))
    _expect_error(_doc([_http(method="POST", form={"n" * 129: "v"})]), "invalid field name")
    _expect_error(_doc([_http(method="POST", form={"n": "v" * 2049})]), "exceeds 2048")
    _expect_error(_doc([_http(method="GET", form={"n": "v"})]), "GET requests cannot carry a form body")

    capture = {"name": "cap", "source": "body", "pattern": "(x)"}
    captures = [dict(capture, name=f"cap{index}") for index in range(16)]
    _roundtrip(_doc([_http(captures=captures)]))
    _expect_error(_doc([_http(captures=captures + [dict(capture, name="cap16")])]), "too many captures")
    _expect_error(
        _doc([_http(captures=[dict(capture), dict(capture)])]),
        "duplicate capture name",
    )
    _roundtrip(
        _doc(
            [
                _http(
                    captures=[
                        {
                            "name": "long",
                            "source": "body",
                            "pattern": "(" + "a" * 398 + ")",
                        }
                    ]
                )
            ]
        )
    )
    _expect_error(
        _doc([_http(captures=[{"name": "long", "source": "body", "pattern": "(" + "a" * 399 + ")"}])]),
        "exceeds 400",
    )

    for unsafe in ("(a+)+$", "(a|aa)+$", "([a-z]+)+$", "(a)\\1", "(?=a)(a)", "(?<=a)(a)"):
        _expect_error(_doc([_http(captures=[{"name": "bad", "source": "body", "pattern": unsafe}])]))
    _roundtrip(
        _doc(
            [
                _http(
                    captures=[
                        {"name": "safe", "source": "body", "pattern": "name=\"item\" value=\"([^\"]+)\""},
                        {"name": "safe2", "source": "body", "pattern": r"([A-Za-z0-9_\-]+)"},
                        {"name": "ctype", "source": "header:Content-Type", "pattern": "(text/html)"},
                        {"name": "ctype_lower", "source": "header:content-type", "pattern": "(text/html)"},
                    ]
                )
            ]
        )
    )

    _roundtrip(
        _doc([_raw(captures=[{"name": "wire", "source": "bytes", "pattern": "(HTTP/1\\.1 [0-9]{3})"}])])
    )
    _expect_error(
        _doc([_raw(captures=[{"name": "ct", "source": "header:Content-Type", "pattern": "(text/html)"}])]),
        "not available for raw_socket",
    )
    _expect_error(
        _doc([_http(captures=[{"name": "wire", "source": "bytes", "pattern": "(x)"}])]),
        "only available for raw_socket",
    )

    _expect_error(_doc([_http(path="/work/?page=1")]))
    _expect_error(_doc([_http(path="//work/")]))
    _expect_error(_doc([_http(path="http://127.0.0.1:9090/work/")]))
    _roundtrip(_doc([_http(path="/" + "a" * 2047)]))
    _expect_error(_doc([_http(path="/" + "a" * 2048)]), "exceeds 2048")

    _expect_error(_doc([_raw(sends=[{"text": "GET / HTTP/1.1\r\nX: a\x00b\r\n\r\n"}])]), "NUL")
    _expect_error(
        _doc([_raw(sends=[{"text": "a" * 16384}, {"text": "b" * 1}])]),
        "raw request bytes exceed",
    )
    _roundtrip(_doc([_raw(sends=[{"text": "a" * 16384}])]))
    eight = [{"text": "x"} for _ in range(8)]
    _roundtrip(_doc([_raw(sends=eight)]))
    _expect_error(_doc([_raw(sends=eight + [{"text": "x"}])]), "1..8")
    _roundtrip(_doc([_raw(read_timeout_ms=100)]))
    _roundtrip(_doc([_raw(read_timeout_ms=2000)]))
    _expect_error(_doc([_raw(read_timeout_ms=99)]), "out of range")
    _expect_error(_doc([_raw(read_timeout_ms=2001)]), "out of range")

    _roundtrip(_doc([_http() for _ in range(20)]))
    _expect_error(_doc([_http() for _ in range(21)]), "1..20")

    _roundtrip(_doc(diagnostic={"apparent_step": 1, "readback_step": 2, "explanation": "x"}, steps=[_http(), _http()]))
    _expect_error(
        _doc(diagnostic={"apparent_step": 2, "readback_step": 1, "explanation": "x"}, steps=[_http(), _http()]),
        "must follow",
    )
    _expect_error(
        _doc(diagnostic={"apparent_step": 1, "readback_step": 3, "explanation": "x"}, steps=[_http(), _http()]),
        "out of range",
    )
