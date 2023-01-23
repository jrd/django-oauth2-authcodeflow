from base64 import urlsafe_b64encode
from hashlib import sha1
from types import FunctionType

from django.core.exceptions import ImproperlyConfigured
from pytest import raises

from oauth2_authcodeflow.conf import (
    Settings,
    get_default_django_username,
    import_string_as_func,
    settings,
)
from oauth2_authcodeflow.views import AuthenticateView


def f1() -> str:
    return 'dotted_import'


def test_import_string_as_func():
    with raises(ImportError, match=r"^Could not import 'f1' for API setting 'test'\. ImportError: f1 doesn't look like a module path\.$"):
        import_string_as_func('f1', 'test')
    with raises(ImportError, match=r"^Could not import 'truc\.f1' for API setting 'test'\. ModuleNotFoundError: No module named 'truc'\.$"):
        import_string_as_func('truc.f1', 'test')
    func = import_string_as_func(f'{__name__}.f1', 'test')
    assert func is f1
    assert func() == f1() == 'dotted_import'


def test_get_default_django_username():
    assert get_default_django_username({}) == urlsafe_b64encode(sha1(b'').digest()).decode('ascii').rstrip('=')
    assert get_default_django_username({'email': 'toto@example.com'}) == urlsafe_b64encode(sha1(b'toto@example.com').digest()).decode('ascii').rstrip('=')


def test_Settings_custom_default(settings):
    settings.TOTO = 'titi'
    settings.FOO = True
    settings.BAZ = 'oauth2_authcodeflow.conf.get_default_django_username'
    defaults = {'TOTO': (str, 'toto'), 'FOO': (float, 4.2), 'BAR': (int, ImproperlyConfigured), 'BAZ': (FunctionType, None)}
    mysettings = Settings(defaults)
    assert mysettings.defaults
    assert mysettings.defaults == defaults
    assert mysettings.DEBUG is False
    assert mysettings.TOTO == 'titi'
    with raises(ImproperlyConfigured, match="^Invalid setting: 'FOO' should be of type <class 'float'> and is of type <class 'bool'>$"):
        mysettings.FOO
    with raises(ImproperlyConfigured, match="^Setting 'BAR' not found, it should be defined$"):
        mysettings.BAR
    f = mysettings.BAZ
    assert f is get_default_django_username


def test_Settings_default(settings):
    mysettings = Settings()
    assert mysettings.DEBUG is False
    with raises(ImproperlyConfigured, match="^Setting 'OIDC_RP_CLIENT_SECRET' not found, it should be defined$"):
        mysettings.OIDC_RP_CLIENT_SECRET
    assert mysettings.OIDC_OP_DISCOVERY_DOCUMENT_URL is None
    assert mysettings.OIDC_OP_EXPECTED_EMAIL_CLAIM == 'email'
    assert mysettings.OIDC_RP_SCOPES == ['openid', 'email', 'profile', 'offline_access']
    assert mysettings.OIDC_DJANGO_USERNAME_FUNC is get_default_django_username
    assert mysettings.OIDC_VIEW_AUTHENTICATE is AuthenticateView
    assert mysettings.OIDC_FIRSTNAME_CLAIM == 'given_name'


def test_settings():
    assert isinstance(settings, Settings)
