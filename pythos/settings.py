"""
Django settings for pythos project.

Generated by 'django-admin startproject' using Django 1.8.4.

For more information on this file, see
https://docs.djangoproject.com/en/1.8/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/1.8/ref/settings/
"""

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Basic configuration settings
PCAP_FOLDER = '/home/scout/ICSsec/sites'

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/1.8/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = '_3@tj1hh_6@90b9^vw&$m1&bz3m(3gjxf7d-fa))q1w=x7ex*k'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True
DEBUG_TOOLBAR = True

ALLOWED_HOSTS = ['localhost']


# Application definition

INSTALLED_APPS = (
    # Django core and contrib apps
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.sites',
    'django.contrib.messages',
    'django.contrib.sitemaps',
    'django.contrib.staticfiles',

    # Third party apps used in the project
    'djangobower',
    'django_tables2',
    'tinymce', # TinyMCE
    'registration', # Auth views and registration app
    'easy_thumbnails', # Thumbnailer
#    'django_otp',
#    'django_otp.plugins.otp_static',
#    'django_otp.plugins.otp_totp',
#    'two_factor',
#    'otp_yubikey',
    'django_nvd3',  # Django Wrapper for NVD3 - It's time for beautiful charts
    'django_rq',

    # Dash core, contrib layouts and apps
    'dash', # Dash core
    'dash.contrib.layouts.android', # Android layout for Dash
    'dash.contrib.layouts.bootstrap2', # Bootstrap 2 layouts for Dash
    # 'dash.contrib.layouts.bootstrap3', # Bootstrap 3 layouts for Dash
    'dash.contrib.layouts.windows8', # Windows 8 layout for Dash
    'dash.contrib.layouts.pythos',
    'dash.contrib.plugins.pythos_barchart',
    'dash.contrib.plugins.pythos_pcap',
    'dash.contrib.plugins.dummy', # Dummy (testing) plugin for Dash
    'dash.contrib.plugins.memo', # Memo plugin for Dash
    'dash.contrib.plugins.image', # Image plugin for Dash
    'dash.contrib.plugins.rss_feed', # RSS feed plugin for Dash
    'dash.contrib.plugins.url', # URL plugin for Dash
    'dash.contrib.plugins.video', # Video plugin for Dash
    'dash.contrib.plugins.weather', # Weather plugin for Dash
    'dash.contrib.apps.public_dashboard', # Public dashboard app for Dash

    # Project specific apps
    'kb',           # System identification (e.g. OS)
    'discovery',    # Capturing network traffic, parse and store relevant data to database
    'config',       # Global configuration (e.g. sites overview, network interfaces)
    'dashboard',    # The pythos command and control center
)

# See djangobower in INSTALLED_APPS
BOWER_INSTALLED_APPS = (
    'jquery#1.9',
    'underscore',
    'd3',
    'nvd3',
)

MIDDLEWARE_CLASSES = (
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
#    'django_otp.middleware.OTPMiddleware',
    'django.contrib.auth.middleware.SessionAuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'django.middleware.security.SecurityMiddleware',
)

ROOT_URLCONF = 'pythos.urls'

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

WSGI_APPLICATION = 'pythos.wsgi.application'


# Database
# https://docs.djangoproject.com/en/1.8/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'pythos',
        'USER': 'pythos',
        'PASSWORD': 'pythos',
        'HOST': 'localhost',
        'PORT': '',
        'CONN_MAX_AGE': 600,
    }
}


# Internationalization
# https://docs.djangoproject.com/en/1.8/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/1.8/howto/static-files/

STATIC_URL = '/static/'
STATIC_ROOT = '/srv/http/pythos/static/'

BOWER_COMPONENTS_ROOT = os.path.join(BASE_DIR, 'components')

STATICFILES_FINDERS = (
    'django.contrib.staticfiles.finders.FileSystemFinder',
    'django.contrib.staticfiles.finders.AppDirectoriesFinder',
    'djangobower.finders.BowerFinder',
)

# Security settings

SECURE_SSL_REDIRECT = False # True
SESSION_COOKIE_SECURE = False # True
CSRF_COOKIE_SECURE = False # True
SECURE_HSTS_SECONDS = 0 # 60
SECURE_HSTS_INCLUDE_SUBDOMAINS = False # True


# Two-factor authentication

#from django.core.urlresolvers import reverse_lazy

#LOGIN_URL = reverse_lazy('two_factor:login')

# django-admin-tools custom dashboard
ADMIN_TOOLS_MENU = 'admin_tools_dashboard.menu.CustomMenu'

ACCOUNT_ACTIVATION_DAYS = 2

# Django RQ
RQ_QUEUES = {
    'default': {
        'HOST': 'localhost',
        'PORT': 6379,
        'DB': 0,
    },
}

# Do not put any settings below this line
try:
    from local_settings import *
except:
    pass

if DEBUG and DEBUG_TOOLBAR:
    try:
        # Make sure the django-debug-toolbar is installed
        import debug_toolbar

        # debug_toolbar
        MIDDLEWARE_CLASSES += (
            'debug_toolbar.middleware.DebugToolbarMiddleware',
        )

        INSTALLED_APPS += (
            'debug_toolbar',
        )

        DEBUG_TOOLBAR_CONFIG = {
            'INTERCEPT_REDIRECTS': False,
        }

    except ImportError:
        pass
