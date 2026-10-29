"""Production settings for the hosted ledger installation.

The application code is the pinned upstream Django Ledger snapshot.  Only
deployment concerns (paths, secrets, static files, logging) live here.
"""
import os
from pathlib import Path

BASE_DIR = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

STATE_DIR = Path(os.environ.get("LEDGER_STATE_DIR", "/var/lib/ledger"))
STATE_DIR.mkdir(parents=True, exist_ok=True)

SECRET_FILE = STATE_DIR / "secret_key"


def _load_secret_key() -> str:
    try:
        value = SECRET_FILE.read_text(encoding="ascii").strip()
    except OSError:
        value = ""
    if len(value) >= 50:
        return value
    from django.core.management.utils import get_random_secret_key

    value = get_random_secret_key()
    try:
        fd = os.open(SECRET_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as stream:
            stream.write(value)
    except OSError:
        pass
    return value


SECRET_KEY = _load_secret_key()
DEBUG = False
ALLOWED_HOSTS = ["127.0.0.1", "localhost"]
CSRF_TRUSTED_ORIGINS = ["http://127.0.0.1:9090", "http://localhost:9090"]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django_ledger",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "deployment.audit_middleware.RequestPrincipalMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "deployment.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "deployment" / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "django_ledger.context.django_ledger_context",
            ],
        },
    },
]

WSGI_APPLICATION = "deployment.wsgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": str(STATE_DIR / "state.sqlite3"),
        "OPTIONS": {"timeout": 20},
    }
}

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "ledger-local",
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "America/New_York"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"
STATIC_ROOT = Path(os.environ.get("LEDGER_STATIC_ROOT", str(BASE_DIR / "staticfiles")))
LOGIN_URL = "/auth/login/"
LOGIN_REDIRECT_URL = "/work/"
LOGOUT_REDIRECT_URL = "/auth/login/"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Use the current (non-deprecated) model API throughout the deployment.
DJANGO_LEDGER_USE_DEPRECATED_BEHAVIOR = False

SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
X_FRAME_OPTIONS = "DENY"
SECURE_CONTENT_TYPE_NOSNIFF = True

# Server and application logs are sidecar-private; never echoed to a client.
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "plain": {"format": "%(asctime)s %(levelname)s %(name)s %(message)s"},
    },
    "handlers": {
        "file": {
            "class": "logging.FileHandler",
            "filename": str(STATE_DIR / "application.log"),
            "formatter": "plain",
            "delay": True,
        },
    },
    "root": {"handlers": ["file"], "level": "WARNING"},
}
