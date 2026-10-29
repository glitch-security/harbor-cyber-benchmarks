"""URL configuration for the hosted ledger installation."""
from django.conf import settings
from django.contrib import admin
from django.urls import include, path
from django.views.static import serve as static_serve

from deployment import views

urlpatterns = [
    path("admin/", admin.site.urls),
    path("work/", views.operations_workspace, name="work"),
    path("static/<path:path>", static_serve, {"document_root": settings.STATIC_ROOT}),
    path("", include("django_ledger.urls", namespace="django_ledger")),
]
