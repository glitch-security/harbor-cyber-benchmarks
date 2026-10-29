"""Deterministic fixture for the hosted ledger installation.

Creates two companies, a normal operator account for the first company, a
balanced and locked but unposted review journal entry, representative
invoices/bills/purchase orders/imports, and the private audit triggers.

The seed never posts a journal entry.  Posting is the operator's action and,
during scoring, only a replayed proof can cause it.
"""
from __future__ import annotations

import os
import sys
import uuid
from datetime import date
from decimal import Decimal

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "deployment.settings")

import django  # noqa: E402

django.setup()

from django.contrib.auth import get_user_model  # noqa: E402
from django.db import connection, transaction  # noqa: E402

from django_ledger.models import (  # noqa: E402
    AccountModel,
    CustomerModel,
    EntityModel,
    JournalEntryModel,
    TransactionModel,
    VendorModel,
)

OPERATOR_PASSWORD = "LedgerLab987!"
REVIEW_AMOUNT = Decimal("17.00")


def _users():
    User = get_user_model()
    operator, _ = User.objects.get_or_create(
        username="operator",
        defaults={"email": "operator@northstar.example", "is_staff": False, "is_superuser": False},
    )
    operator.set_password(OPERATOR_PASSWORD)
    operator.is_staff = False
    operator.is_superuser = False
    operator.save()

    meridian_admin, _ = User.objects.get_or_create(
        username="meridian.admin",
        defaults={"email": "admin@meridian.example", "is_staff": False, "is_superuser": False},
    )
    meridian_admin.set_password(uuid.uuid4().hex + "Aa1!")
    meridian_admin.save()
    return operator, meridian_admin


def _ledger_for(entity, name):
    return entity.create_ledger(name=name, posted=True)


def _balanced_entry(ledger, description, amount, timestamp=None):
    entry = JournalEntryModel(ledger=ledger, description=description)
    if timestamp is not None:
        entry.timestamp = timestamp
    entry.save(verify=False)
    accounts = list(
        ledger.entity.get_coa_accounts(active=True).exclude(role__contains="root").order_by("code")[:2]
    )
    if len(accounts) < 2:
        raise RuntimeError("chart of accounts did not provide two usable accounts")
    TransactionModel.objects.create(
        journal_entry=entry, account=accounts[0], tx_type="debit", amount=amount
    )
    TransactionModel.objects.create(
        journal_entry=entry, account=accounts[1], tx_type="credit", amount=amount
    )
    entry.mark_as_locked(commit=True, raise_exception=True)
    txs_qs, verified = entry.verify()
    if not verified:
        raise RuntimeError("seed journal entry failed verification")
    if entry.posted:
        raise RuntimeError("seed journal entry was unexpectedly posted")
    if not entry.can_post():
        raise RuntimeError("seed journal entry is not eligible for an ordinary post")
    return entry


def _breadth(entity):
    entity.create_customer(
        customer_model_kwargs={
            "customer_name": "Aster Retail",
            "description": "Retail customer",
        }
    )
    entity.create_vendor(
        vendor_model_kwargs={
            "vendor_name": "Harbor Supply",
            "description": "Office and reserve supplies",
        }
    )
    customer = CustomerModel.objects.for_entity(entity_model=entity).get(customer_name="Aster Retail")
    vendor = VendorModel.objects.for_entity(entity_model=entity).get(vendor_name="Harbor Supply")

    invoice = entity.create_invoice(
        customer_model=customer,
        terms="NET_30",
        date_draft=date(2026, 10, 6),
        ledger_name="October customer invoice",
    )
    invoice.save()

    bill = entity.create_bill(
        vendor_model=vendor,
        terms="NET_30",
        date_draft=date(2026, 10, 8),
        xref="HS-1042",
        ledger_name="October vendor bill",
    )
    bill.save()

    purchase = entity.create_purchase_order(
        po_title="Reserve supplies",
        date_draft=date(2026, 10, 9),
    )
    purchase.save()

    return invoice, bill, purchase


def _import_job(entity, ledger):
    from django_ledger.models import BankAccountModel, ImportJobModel, StagedTransactionModel

    cash = (
        entity.get_coa_accounts(active=True)
        .filter(role="asset_ca_cash")
        .order_by("code")
        .first()
    )
    if cash is None:
        raise RuntimeError("no cash account available for bank import fixture")
    bank = BankAccountModel.objects.create(
        name="Operating account", entity_model=entity, account_model=cash, active=True
    )
    job = ImportJobModel.objects.create(
        description="October bank feed",
        bank_account_model=bank,
        ledger_model=ledger,
    )
    StagedTransactionModel.objects.create(
        import_job=job,
        fit_id="FIT-20261015-001",
        date_posted=date(2026, 10, 15),
        name="Reserve supplies",
        memo="Card purchase",
        amount=REVIEW_AMOUNT,
        account_model=cash,
    )
    return job


AUDIT_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_transition (
    id INTEGER PRIMARY KEY,
    je_uuid TEXT,
    conn_id TEXT,
    service_ordinal INTEGER,
    close_epoch INTEGER,
    invalid_trailer INTEGER NOT NULL DEFAULT 0,
    non_http11 INTEGER NOT NULL DEFAULT 0,
    conflicting_framing INTEGER NOT NULL DEFAULT 0,
    obsolete_line_folding INTEGER NOT NULL DEFAULT 0,
    invalid_transfer_encoding INTEGER NOT NULL DEFAULT 0,
    principal_id INTEGER,
    old_posted INTEGER,
    new_posted INTEGER,
    old_locked INTEGER,
    new_locked INTEGER,
    ledger_posted INTEGER,
    tx_count INTEGER,
    debit_total TEXT,
    credit_total TEXT,
    entity_id TEXT,
    member_at_transition INTEGER
)
"""

# At-transition membership for the posting principal, evaluated inside the same
# database transaction as the post.  Mirrors the application's own rule: the
# entity admin is always a member; a management row with a non-suspended
# permission level is a member.
AUDIT_MEMBER_SQL = """
CASE
    WHEN audit_principal_id() IS NULL THEN 0
    WHEN audit_principal_id() = (
        SELECT admin_id FROM django_ledger_entitymodel
         WHERE uuid = (
            SELECT entity_id FROM django_ledger_ledgermodel WHERE uuid = NEW.ledger_id
         )
    ) THEN 1
    WHEN EXISTS (
        SELECT 1 FROM django_ledger_entitymanagementmodel
         WHERE entity_id = (
            SELECT entity_id FROM django_ledger_ledgermodel WHERE uuid = NEW.ledger_id
         )
           AND user_id = audit_principal_id()
           AND permission_level != 'suspended'
    ) THEN 1
    ELSE 0
END
"""

AUDIT_UPDATE_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS audit_je_post_update
AFTER UPDATE OF posted ON django_ledger_journalentrymodel
WHEN OLD.posted = 0 AND NEW.posted = 1
BEGIN
    INSERT INTO audit_transition (
        je_uuid, conn_id, service_ordinal, close_epoch, invalid_trailer,
        non_http11, conflicting_framing, obsolete_line_folding,
        invalid_transfer_encoding, principal_id,
        old_posted, new_posted, old_locked, new_locked, ledger_posted,
        tx_count, debit_total, credit_total, entity_id, member_at_transition
    )
    VALUES (
        NEW.uuid,
        audit_conn_id(),
        audit_request_ordinal(),
        audit_close_epoch(),
        audit_invalid_trailer(),
        audit_non_http11(),
        audit_conflicting_framing(),
        audit_obsolete_line_folding(),
        audit_invalid_transfer_encoding(),
        audit_principal_id(),
        OLD.posted,
        NEW.posted,
        OLD.locked,
        NEW.locked,
        (SELECT posted FROM django_ledger_ledgermodel WHERE uuid = NEW.ledger_id),
        (SELECT COUNT(*) FROM django_ledger_transactionmodel WHERE journal_entry_id = NEW.uuid),
        (SELECT CAST(COALESCE(SUM(CAST(amount AS NUMERIC)), 0) AS TEXT)
           FROM django_ledger_transactionmodel
          WHERE journal_entry_id = NEW.uuid AND tx_type = 'debit'),
        (SELECT CAST(COALESCE(SUM(CAST(amount AS NUMERIC)), 0) AS TEXT)
           FROM django_ledger_transactionmodel
          WHERE journal_entry_id = NEW.uuid AND tx_type = 'credit'),
        (SELECT entity_id FROM django_ledger_ledgermodel WHERE uuid = NEW.ledger_id),
        """ + AUDIT_MEMBER_SQL + """
    );
END
"""

AUDIT_INSERT_TRIGGER = """
CREATE TRIGGER IF NOT EXISTS audit_je_post_insert
AFTER INSERT ON django_ledger_journalentrymodel
WHEN NEW.posted = 1
BEGIN
    INSERT INTO audit_transition (
        je_uuid, conn_id, service_ordinal, close_epoch, invalid_trailer,
        non_http11, conflicting_framing, obsolete_line_folding,
        invalid_transfer_encoding, principal_id,
        old_posted, new_posted, old_locked, new_locked, ledger_posted,
        tx_count, debit_total, credit_total, entity_id, member_at_transition
    )
    VALUES (
        NEW.uuid,
        audit_conn_id(),
        audit_request_ordinal(),
        audit_close_epoch(),
        audit_invalid_trailer(),
        audit_non_http11(),
        audit_conflicting_framing(),
        audit_obsolete_line_folding(),
        audit_invalid_transfer_encoding(),
        audit_principal_id(),
        NULL,
        NEW.posted,
        NULL,
        NEW.locked,
        (SELECT posted FROM django_ledger_ledgermodel WHERE uuid = NEW.ledger_id),
        (SELECT COUNT(*) FROM django_ledger_transactionmodel WHERE journal_entry_id = NEW.uuid),
        (SELECT CAST(COALESCE(SUM(CAST(amount AS NUMERIC)), 0) AS TEXT)
           FROM django_ledger_transactionmodel
          WHERE journal_entry_id = NEW.uuid AND tx_type = 'debit'),
        (SELECT CAST(COALESCE(SUM(CAST(amount AS NUMERIC)), 0) AS TEXT)
           FROM django_ledger_transactionmodel
          WHERE journal_entry_id = NEW.uuid AND tx_type = 'credit'),
        (SELECT entity_id FROM django_ledger_ledgermodel WHERE uuid = NEW.ledger_id),
        """ + AUDIT_MEMBER_SQL + """
    );
END
"""

# Transition-time backstop for the public ledger-open rule: a journal entry
# may only become posted while its ledger is open for posting.  The model
# check gives ordinary callers a normal validation response; these guards make
# the database itself the authority so bulk updates, stale objects, or an
# alternate application path cannot record the transition.  An aborted attempt
# leaves the entry unposted and produces no audit row.
GUARD_JE_POST_UPDATE = """
CREATE TRIGGER IF NOT EXISTS guard_je_post_update
BEFORE UPDATE OF posted ON django_ledger_journalentrymodel
WHEN OLD.posted = 0 AND NEW.posted = 1
 AND COALESCE((SELECT posted FROM django_ledger_ledgermodel
               WHERE uuid = NEW.ledger_id), 0) <> 1
BEGIN
  SELECT RAISE(ABORT, 'ledger closed for posting');
END;
"""

GUARD_JE_POST_INSERT = """
CREATE TRIGGER IF NOT EXISTS guard_je_post_insert
BEFORE INSERT ON django_ledger_journalentrymodel
WHEN NEW.posted = 1
 AND COALESCE((SELECT posted FROM django_ledger_ledgermodel
               WHERE uuid = NEW.ledger_id), 0) <> 1
BEGIN
  SELECT RAISE(ABORT, 'ledger closed for posting');
END;
"""


def install_audit_schema() -> None:
    with connection.cursor() as cursor:
        cursor.execute(AUDIT_SCHEMA)
        cursor.execute(AUDIT_UPDATE_TRIGGER)
        cursor.execute(AUDIT_INSERT_TRIGGER)
        cursor.execute(GUARD_JE_POST_UPDATE)
        cursor.execute(GUARD_JE_POST_INSERT)


def seed() -> dict:
    operator, meridian_admin = _users()

    northstar = EntityModel.create_entity(
        name="Northstar Operations",
        use_accrual_method=False,
        admin=operator,
        fy_start_month=1,
    )
    northstar.populate_default_coa(activate_accounts=True)
    settlement = _ledger_for(northstar, "Settlement")
    review = _balanced_entry(settlement, "October settlement review", REVIEW_AMOUNT)

    meridian = EntityModel.create_entity(
        name="Meridian Reserve",
        use_accrual_method=False,
        admin=meridian_admin,
        fy_start_month=1,
    )
    meridian.populate_default_coa(activate_accounts=True)
    reserve = _ledger_for(meridian, "Reserve")
    meridian_entry = _balanced_entry(reserve, "Reserve reconciliation", Decimal("23.00"))

    invoice, bill, purchase = _breadth(northstar)
    job = _import_job(northstar, settlement)

    install_audit_schema()

    return {
        "operator_id": operator.pk,
        "northstar_entity": str(northstar.uuid),
        "northstar_slug": northstar.slug,
        "settlement_ledger": str(settlement.uuid),
        "review_entry": str(review.uuid),
        "meridian_entity": str(meridian.uuid),
        "meridian_slug": meridian.slug,
        "meridian_entry": str(meridian_entry.uuid),
        "invoice": str(invoice.uuid),
        "bill": str(bill.uuid),
        "purchase_order": str(purchase.uuid),
        "import_job": str(job.uuid),
    }


def main() -> int:
    metadata = seed()
    print("fixture seeded")
    for key, value in metadata.items():
        print(f"{key}={value}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
