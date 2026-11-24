import sys
from pathlib import Path

from decouple import AutoConfig
from dj_database_url import parse as parse_database_url

BASE_DIR = Path(__file__).resolve().parent.parent
config = AutoConfig(search_path=str(BASE_DIR))


def csv_setting(name, default=""):
    value = config(name, default=default)
    if isinstance(value, list):
        return value
    return [item.strip() for item in str(value).split(",") if item.strip()]


SECRET_KEY = config("SECRET_KEY", default="dev-only-insecure-secret-change-before-production")
DEBUG = config("DEBUG", default=True, cast=bool)
TESTING = config("TESTING", default=False, cast=bool) or "test" in sys.argv or "pytest" in sys.argv
ALLOWED_HOSTS = csv_setting("ALLOWED_HOSTS", "localhost,127.0.0.1")
CSRF_TRUSTED_ORIGINS = csv_setting("CSRF_TRUSTED_ORIGINS", "http://localhost:8000")
CORS_ALLOWED_ORIGINS = csv_setting("CORS_ALLOWED_ORIGINS", "")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "rest_framework.authtoken",
    "drf_spectacular",
    "corsheaders",
    "whitenoise",
    "accounts",
    "organizations",
    "cloud_accounts",
    "cloud_scanner",
    "iam_analyzer",
    "risk_engine",
    "compliance",
    "reports",
    "dashboard",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "organizations.middleware.OrganizationContextMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "organizations.context_processors.cloudsentry_context",
            ],
        },
    },
]

DATABASE_URL = config(
    "DATABASE_URL",
    default="postgres://cloudsentry:cloudsentry@localhost:5432/cloudsentry",
)
DATABASES = {"default": parse_database_url(DATABASE_URL)}
if TESTING:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": ":memory:",
        }
    }
DATABASES["default"]["CONN_MAX_AGE"] = 600 if not TESTING else 0
DATABASES["default"]["ATOMIC_REQUESTS"] = False

AUTH_USER_MODEL = "accounts.User"
ALLOW_PUBLIC_REGISTRATION = config("ALLOW_PUBLIC_REGISTRATION", default=True, cast=bool)
AUTHENTICATION_BACKENDS = ["django.contrib.auth.backends.ModelBackend"]
LOGIN_URL = "accounts:login"
LOGIN_REDIRECT_URL = "dashboard:index"
LOGOUT_REDIRECT_URL = "accounts:login"

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 12}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "static"]
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage"
        if not DEBUG
        else "whitenoise.storage.CompressedStaticFilesStorage"
    },
}

MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"
REPORTS_ROOT = MEDIA_ROOT / "reports"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.SessionAuthentication",
        "rest_framework.authentication.TokenAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 25,
    "EXCEPTION_HANDLER": "config.exception_handler.api_exception_handler",
    "DEFAULT_THROTTLE_CLASSES": [],
    "DEFAULT_THROTTLE_RATES": {},
}

SPECTACULAR_SETTINGS = {
    "TITLE": "CloudSentry API",
    "DESCRIPTION": "AI-powered cloud security posture management REST API.",
    "VERSION": "1.0.0",
    "SERVE_INCLUDE_SCHEMA": False,
    "SECURITY": [{"Token": []}, {"CookieAuth": []}],
    "SECURITY_SCHEMES": {
        "Token": {"type": "http", "scheme": "bearer"},
        "CookieAuth": {"type": "apiKey", "in": "cookie", "name": "sessionid"},
    },
}

CLOUDSENTRY = {
    "DEMO_MODE": config("DEMO_MODE", default=True, cast=bool),
    "FIELD_ENCRYPTION_KEY": config("FIELD_ENCRYPTION_KEY", default=""),
    "READ_ONLY_MODE": True,
    "AI_EXPLANATIONS_ENABLED": config("AI_EXPLANATIONS_ENABLED", default=False, cast=bool),
    "GEMINI_API_KEY": config("GEMINI_API_KEY", default=""),
    "GEMINI_MODEL": config("GEMINI_MODEL", default="gemini-1.5-flash"),
    "PROWLER_BIN": config("PROWLER_BIN", default=""),
    "SCAN_TIMEOUT_SECONDS": config("SCAN_TIMEOUT_SECONDS", default=300, cast=int),
    "AWS_DEFAULT_REGION": config("AWS_DEFAULT_REGION", default="us-east-1"),
}

SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SECURE = not DEBUG
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_HSTS_SECONDS = 31536000 if not DEBUG else 0
SECURE_HSTS_INCLUDE_SUBDOMAINS = not DEBUG
SECURE_HSTS_PRELOAD = not DEBUG
X_FRAME_OPTIONS = "DENY"
DATA_UPLOAD_MAX_MEMORY_SIZE = 5 * 1024 * 1024

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {"format": "%(asctime)s %(levelname)s %(name)s %(message)s"},
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "standard",
        },
    },
    "root": {
        "handlers": ["console"],
        "level": config("LOG_LEVEL", default="INFO"),
    },
    "loggers": {
        "django.request": {
            "handlers": ["console"],
            "level": "WARNING",
            "propagate": False,
        },
        "cloudsentry": {
            "handlers": ["console"],
            "level": config("LOG_LEVEL", default="INFO"),
            "propagate": False,
        },
    },
}

if not DEBUG and not TESTING:
    secret = config("SECRET_KEY", default="")
    if len(secret) < 50:
        raise RuntimeError("SECRET_KEY must be at least 50 characters in production.")
