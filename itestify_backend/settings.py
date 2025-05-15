from dotenv import load_dotenv
import os
import dj_database_url
from pathlib import Path
from datetime import timedelta
from decouple import config
from celery.schedules import crontab


load_dotenv()
# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

AUTH_USER_MODEL = 'user.User'

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.getenv('SECRET_KEY')

DEBUG = True

# SECURITY WARNING: don't run with debug turned on in production!

ALLOWED_HOSTS = ["*"]

# Application definition

INSTALLED_APPS = [
    'daphne',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'user',
    'admin_accounts',
    'testimonies',
    'scriptures',
    'rest_framework',
    "rest_framework.authtoken",
    "rest_framework_simplejwt",
    "corsheaders",
    "donations",
    "common",
    "django_celery_beat",
    "django_celery_results",
    # "rest_framework.authtoken",
    'rest_framework_simplejwt.token_blacklist',  # JWT token blacklist
    'reviews',
    'django_filters'
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'itestify_backend.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'itestify_backend.wsgi.application'
ASGI_APPLICATION = "itestify_backend.asgi.application"


# Database
# https://docs.djangoproject.com/en/5.1/ref/settings/#databases

DEPLOY = True

if not DEPLOY:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }
else:
    DATABASES = {
        "default": dj_database_url.parse(os.getenv("POSTGRESDB"))
    }


# REDIS SETTINGS
CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {
            "hosts": [("localhost", 6379)],
        },
    },
}

# Password validation
# https://docs.djangoproject.com/en/5.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'Africa/Lagos'

# TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


LOCALE_PATHS = (os.path.join(BASE_DIR, "locale"),)

CORS_ORIGIN_ALLOW_ALL = True
CORS_ALLOW_CREDENTIALS = True
CORS_ALLOW_ALL_ORIGINS = True

USE_X_FORWARDED_HOST = True
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")


DATE_INPUT_FORMATS = ["%d-%m-%Y"]

REST_USE_JWT = True


REST_FRAMEWORK = {
    "NON_FIELD_ERRORS_KEY": "error",
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.LimitOffsetPagination",
    "PAGE_SIZE": 50,
    "DEFAULT_AUTHENTICATION_CLASSES": (
        "rest_framework_simplejwt.authentication.JWTAuthentication",
        "rest_framework.authentication.TokenAuthentication",
        "rest_framework.authentication.SessionAuthentication",
        # "dj_rest_auth.jwt_auth.JWTCookieAuthentication",
    ),
    'DEFAULT_FILTER_BACKENDS': ['django_filters.rest_framework.DjangoFilterBackend'],
}


AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
]

APPEND_SLASH = False

SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(days=365),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=1),
    "ROTATE_REFRESH_TOKENS": False,
    "BLACKLIST_AFTER_ROTATION": True,
    "USE_BLACKLIST": True,
    "UPDATE_LAST_LOGIN": False,
    "ALGORITHM": "HS256",
    "SIGNING_KEY": SECRET_KEY,
    "VERIFYING_KEY": None,
    "AUDIENCE": None,
    "ISSUER": None,
    "JWK_URL": None,
    "LEEWAY": 0,
    "AUTH_HEADER_TYPES": ("Bearer",),
    "AUTH_HEADER_NAME": "HTTP_AUTHORIZATION",
    "USER_ID_FIELD": "id",
    "USER_ID_CLAIM": "user_id",
    "USER_AUTHENTICATION_RULE": "rest_framework_simplejwt.authentication.default_user_authentication_rule",
    "AUTH_TOKEN_CLASSES": ("rest_framework_simplejwt.tokens.AccessToken",),
    "TOKEN_TYPE_CLAIM": "token_type",
    "TOKEN_USER_CLASS": "rest_framework_simplejwt.models.TokenUser",
    "JTI_CLAIM": "jti",
    "SLIDING_TOKEN_REFRESH_EXP_CLAIM": "refresh_exp",
    "SLIDING_TOKEN_LIFETIME": timedelta(minutes=5),
    "SLIDING_TOKEN_REFRESH_LIFETIME": timedelta(days=1),
}


# CORS
CORS_ALLOW_METHODS = [
    "DELETE",
    "GET",
    "OPTIONS",
    "PATCH",
    "POST",
    "PUT",
]

CORS_ALLOW_HEADERS = [
    "accept",
    "accept-encoding",
    "authorization",
    "content-type",
    "dnt",
    "origin",
    "user-agent",
    "x-csrftoken",
    "x-requested-with",
]


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.1/howto/static-files/

STATIC_URL = 'static/'

# Tell Django to copy static assets into a path called `staticfiles` (this is specific to Render)
if not DEBUG:
    STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
    # Enable the WhiteNoise storage backend, which compresses static files to reduce disk use
    # and renames the files with unique names for each version to support long-term caching
    STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

MEDIA_URL = "/media/"
MEDIA_ROOT = os.path.join(BASE_DIR, "media")

# Default primary key field type
# https://docs.djangoproject.com/en/5.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
# CSRF NAME: Prefer the Laravel Style
CSRF_HEADER_NAME = "HTTP_X_CSRF_TOKEN"

# Email
EMAIL_OTP_EXPIRE_SECONDS = 300

# Email Configuration
EMAIL_USE_SSL = True
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 465
EMAIL_HOST_USER = os.getenv("EMAIL_HOST_USER")
EMAIL_HOST_PASSWORD = os.getenv("EMAIL_HOST_PASSWORD")


# celery settings
CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL")
CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND")
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_TIMEZONE = "Africa/Lagos"
CELERY_BEAT_SCHEDULE = {
    "upload_schedule_videos": {
        "task": "testimonies.tasks.display_name",
        "schedule": crontab(minute="*/2"),  # 5min
        # "schedule": 5, #5 sec
        # "args": [""]
    }
}
CELERY_BEAT_SCHEDULER = 'django_celery_beat.schedulers.DatabaseScheduler'
