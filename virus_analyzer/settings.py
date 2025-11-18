import os
from pathlib import Path
import dj_database_url
from dotenv import load_dotenv
from datetime import timedelta

# Charge les variables d'environnement depuis .env
load_dotenv()

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.getenv('SECRET_KEY', 'django-insecure-default-key-change-me')
DEBUG = os.getenv('DEBUG', 'True') == 'True'

ALLOWED_HOSTS = ['127.0.0.1', 'localhost']
# S'il est déployé, ajoutez votre domaine
# ALLOWED_HOSTS.append(os.getenv('DEPLOYED_HOST'))

# Définition des applications
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    # Apps tierces pour l'API
    'rest_framework',
    'rest_framework.authtoken',
    'rest_framework_simplejwt',
    'dj_rest_auth',
    'django.contrib.sites',  # Requis par dj-rest-auth
    'allauth',  # Requis par dj-rest-auth
    'allauth.account',  # Requis par dj-rest-auth
    'dj_rest_auth.registration',  # Requis par dj-rest-auth
    'corsheaders',  # Pour autoriser les requêtes Angular (UNE SEULE FOIS)

    # Vos applications
    'vt_analyzer',
]

# SITE_ID requis pour 'django.contrib.sites'
SITE_ID = 1

# MIDDLEWARE (défini UNE SEULE FOIS)
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'corsheaders.middleware.CorsMiddleware',  # CORS en premier après security
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'vt_analyzer.middleware.DisableCSRFMiddleware',  # Votre middleware personnalisé
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'allauth.account.middleware.AccountMiddleware',
]

ROOT_URLCONF = 'virus_analyzer.urls'

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

WSGI_APPLICATION = 'virus_analyzer.wsgi.application'

# Base de données (utilise dj_database_url pour lire .env)
DATABASES = {
    'default': dj_database_url.config(default=f"sqlite:///{BASE_DIR / 'db.sqlite3'}")
}

# Modèle d'utilisateur personnalisé
AUTH_USER_MODEL = 'vt_analyzer.User'

# Validation de mot de passe
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',},
]

# Internationalisation
LANGUAGE_CODE = 'fr-fr'
TIME_ZONE = 'Europe/Paris'
USE_I18N = True
USE_TZ = True

# Fichiers statiques et médias
STATIC_URL = 'static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# ===================================================================
# CONFIGURATION DE L'API REST (DRF, JWT, CORS)
# ===================================================================

# Configuration CSRF
CSRF_COOKIE_SECURE = False
CSRF_COOKIE_HTTPONLY = False
SESSION_COOKIE_SECURE = False
CSRF_TRUSTED_ORIGINS = ['http://127.0.0.1:8000', 'http://localhost:8000', 'http://localhost:4200']
CSRF_EXEMPT_URLS = [
    r'^api/',
]

# Configuration CORS (Qui peut appeler votre API)
CORS_ALLOWED_ORIGINS = os.getenv('CORS_ALLOWED_ORIGINS', 'http://localhost:4200').split(',')
CORS_ALLOW_CREDENTIALS = True  # Autorise les cookies (pour l'authentification)
CORS_ALLOW_ALL_ORIGINS = False  # Mettre True seulement en développement si nécessaire

# Configuration Django Rest Framework
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
        'rest_framework.authentication.SessionAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
    'DEFAULT_PAGINATION_CLASS': 'rest_framework.pagination.PageNumberPagination',
    'PAGE_SIZE': 20
}

# Configuration Simple JWT (Tokens)
SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=60),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=7),
}

# Configuration dj-rest-auth
REST_AUTH = {
    'USE_JWT': True,
    'JWT_AUTH_HTTPONLY': False,
    'USER_DETAILS_SERIALIZER': 'vt_analyzer.serializers.UserDetailsSerializer',
    'LOGIN_SERIALIZER': 'dj_rest_auth.serializers.LoginSerializer',
    'SESSION_LOGIN': False,  # Désactive la session login
}

# Configuration Allauth (nécessaire pour dj-rest-auth)
ACCOUNT_USER_MODEL_USERNAME_FIELD = 'username'  # Utilise 'username'
ACCOUNT_EMAIL_REQUIRED = True
ACCOUNT_USERNAME_REQUIRED = True  # 'username' est requis
ACCOUNT_AUTHENTICATION_METHOD = 'username_email'  # S'authentifier avec l'un ou l'autre
ACCOUNT_EMAIL_VERIFICATION = 'none'  # Mettez 'mandatory' en production
EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'  # Pour le dev

# ===================================================================
# VOS CLÉS API (Chargées depuis .env)
# ===================================================================
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
OTX_API_KEY = os.getenv('OTX_API_KEY')
IPINFO_TOKEN = os.getenv('IPINFO_TOKEN')