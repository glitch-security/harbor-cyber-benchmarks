"""Small operations workspace for the hosted installation.

This view is ordinary product integration code: it requires a signed-in
operator and links to the existing entity, ledger, journal, invoice, bill,
purchase-order, chart, import and report routes provided by the application.
It performs no authorization decisions of its own beyond login.
"""
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.urls import reverse

from django_ledger.models import EntityModel, JournalEntryModel


def _first_entity(user):
    return (
        EntityModel.objects.for_user(user_model=user)
        .order_by("name")
        .first()
    )


@login_required
def operations_workspace(request):
    entity = _first_entity(request.user)
    context = {
        "entity": entity,
        "ledger": None,
        "review_entry": None,
        "links": [],
    }
    if entity is not None:
        ledgers = list(entity.ledgermodel_set.order_by("name"))
        ledger = next((l for l in ledgers if l.name == "Settlement"), None)
        if ledger is None and ledgers:
            ledger = ledgers[0]
        context["ledger"] = ledger
        context["ledgers"] = ledgers
        slug = entity.slug
        context["links"] = [
            ("Entity dashboard", reverse("django_ledger:entity-dashboard", kwargs={"entity_slug": slug})),
            ("Ledgers", reverse("django_ledger:ledger-list", kwargs={"entity_slug": slug})),
            ("Chart of accounts", reverse("django_ledger:coa-list", kwargs={"entity_slug": slug})),
            ("Invoices", reverse("django_ledger:invoice-list", kwargs={"entity_slug": slug})),
            ("Bills", reverse("django_ledger:bill-list", kwargs={"entity_slug": slug})),
            ("Purchase orders", reverse("django_ledger:po-list", kwargs={"entity_slug": slug})),
            ("Bank imports", reverse("django_ledger:import-job-list", kwargs={"entity_slug": slug})),
            ("Balance sheet", reverse("django_ledger:entity-bs", kwargs={"entity_slug": slug})),
            ("Income statement", reverse("django_ledger:entity-ic", kwargs={"entity_slug": slug})),
            ("Cash flow", reverse("django_ledger:entity-cf", kwargs={"entity_slug": slug})),
        ]
        if ledger is not None:
            review = (
                JournalEntryModel.objects.for_entity(entity_model=entity)
                .for_ledger(ledger_pk=ledger.uuid)
                .filter(posted=False)
                .order_by("timestamp")
                .first()
            )
            context["review_entry"] = review
    return render(request, "deployment/work.html", context)
