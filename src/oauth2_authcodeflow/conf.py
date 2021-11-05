from base64 import urlsafe_b64encode
from hashlib import sha1
from typing import (
    Callable,
    Dict,
    Union,
)

from django.conf import settings as dj_settings
from django.core.exceptions import ImproperlyConfigured
from django.utils.module_loading import import_string

from . import constants  # noqa F401


def import_string_if_not_func(value: Union[str, Callable], attr: str) -> Callable:
    try:
        return value if callable(value) else import_string(value)
    except ImportError as e:
        raise ImportError(f"Could not import '{value}' for API setting '{attr}'. {e.__class__.__name__}: {e}.")


def get_default_django_username(claims: Dict) -> str:
    """base64 encode of the email hash (sha1)"""
    return urlsafe_b64encode(
        sha1(claims.get('email', '').encode('utf8')).digest()
    ).decode('ascii').rstrip('=')


DEFAULTS = {
    'OIDC_VIEW_AUTHENTICATE': f'{__package__}.views.AuthenticateView',
    'OIDC_VIEW_CALLBACK': f'{__package__}.views.CallbackView',
    'OIDC_VIEW_LOGOUT': f'{__package__}.views.LogoutView',
    'OIDC_VIEW_TOTAL_LOGOUT': f'{__package__}.views.TotalLogoutView',
    'OIDC_VIEW_LOGOUT_BY_OP': f'{__package__}.views.LogoutByOPView',
    # URL of your OpenID connect Provider discovery document url (recommended).
    # If you provide this, the following configs will be ignored:
    # - `OIDC_OP_AUTHORIZATION_URL`
    # - `OIDC_OP_TOKEN_URL`
    # - `OIDC_OP_USERINFO_URL`
    # - `OIDC_OP_JWKS_URL`
    'OIDC_OP_DISCOVERY_DOCUMENT_URL': None,
    # URL of your OpenID connect Provider authorization endpoint (not recommended, `OIDC_OP_DISCOVERY_DOCUMENT_URL` is preferred).
    'OIDC_OP_AUTHORIZATION_URL': None,
    # URL of your OpenID connect Provider token endpoint (not recommended, `OIDC_OP_DISCOVERY_DOCUMENT_URL` is preferred).
    'OIDC_OP_TOKEN_URL': None,
    # URL of your OpenID connect Provider userinfo endpoint (not recommended, `OIDC_OP_DISCOVERY_DOCUMENT_URL` is preferred).
    'OIDC_OP_USERINFO_URL': None,
    # URL of your OpenId connect Provider endpoint to get public signing keys (in `PEM` or `DER` format).
    # This is used to verify the `id_token`.
    # This is not recommended to provide this url here but rather use `OIDC_OP_DISCOVERY_DOCUMENT_URL` config.
    'OIDC_OP_JWKS_URL': None,
    # URL of your OpenID connect Provider end session endpoint (not recommended, `OIDC_OP_DISCOVERY_DOCUMENT_URL` is preferred).
    'OIDC_OP_END_SESSION_URL': None,
    # Fetch user info on login or not.
    'OIDC_OP_FETCH_USER_INFO': True,
    # Do a call to total logout will call the OP for a logout. Default true.
    # Be careful, some OP will not follow the RFC and will not allow the user to NOT logout all connected apps.
    # Azure is such a bad example.
    'OIDC_OP_TOTAL_LOGOUT': True,
    # expected email key.
    'OIDC_OP_EXPECTED_EMAIL_CLAIM': 'email',
    # `OIDC_OP_EXPECTED_EMAIL_CLAIM` value is automatically included in this list.
    'OIDC_OP_EXPECTED_CLAIMS': [],
    # OpenID Connect client ID provided for your Relaying Party/client by your OpenIdConnect Provider
    'OIDC_RP_CLIENT_ID': ImproperlyConfigured,
    # OpenID Connect client secret provided for your Relaying Party/client by your OpenIdConnect Provider
    'OIDC_RP_CLIENT_SECRET': ImproperlyConfigured,
    # `PKCE` improve security, disable it only if your provider cannot handle it.
    'OIDC_RP_USE_PKCE': True,
    # Force to ask for consent on login, even if `offline_access` is not in scopes
    'OIDC_RP_FORCE_CONSENT_PROMPT': False,
    # The OpenID Connect scopes to request during login.
    # The scopes could be usefull later to get access to other ressources.
    # `openid` must be in the list.
    # You can also include the `email` scope to ensure that the email field will be in the claims (recommended).
    # You can also include the `profile` scope to get more (like names, …) info in the `id_token` (recommended).
    # You can also get a `refresh_token` by specifying the `offline_access` scope.
    'OIDC_RP_SCOPES': ['openid', 'email', 'profile', 'offline_access'],
    # Sets the algorithms the IdP may use to sign ID tokens.
    # Typical values ar 'HS256' (no key required) and 'RS256' (public key required)
    # The public keys might be defined in `OIDC_RP_IDP_SIGN_KEY` or deduced using the `OIDC_OP_JWKS_URL` config.
    'OIDC_RP_SIGN_ALGOS_ALLOWED': ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512'],
    # Public RSA used to verify signatures. Overrides keys from JWKS endpoint.
    # Should be in PEM or DER format.
    'OIDC_RP_IDP_SIGN_KEY': None,
    # Enables or disables automatic user creation during authentication
    'OIDC_CREATE_USER': True,
    # Sets the length of the random string used in the OAuth2 protocol.
    'OIDC_RANDOM_SIZE': 32,
    # Defines a proxy for all requests to the OpenID Connect provider (fetch JWS, retrieve JWT tokens, Userinfo Endpoint).
    # The default is set to None which means the library will not use a proxy and connect directly.
    # For configuring a proxy check the Python requests documentation: https://requests.readthedocs.io/en/master/user/advanced/#proxies
    'OIDC_PROXY': None,
    # Defines a timeout for all requests to the OpenID Connect provider (fetch JWS, retrieve JWT tokens, Userinfo Endpoint).
    # The default is set to None which means the library will wait indefinitely.
    # The time can be defined as seconds (integer).
    # More information about possible configuration values, see Python requests: https://requests.readthedocs.io/en/master/user/quickstart/#timeouts
    'OIDC_TIMEOUT': None,
    # Sets the GET parameter that is being used to define the redirect URL after succesful authentication
    'OIDC_REDIRECT_OK_FIELD_NAME': 'next',
    # Sets the GET parameter that is being used to define the redirect URL after failed authentication
    'OIDC_REDIRECT_ERROR_FIELD_NAME': 'fail',
    # Function or dotted path to a function that compute the django username based on claims.
    # The username should be unique for this app.
    # The default is to use a base64 encode of the email hash (sha1).
    'OIDC_DJANGO_USERNAME_FUNC': get_default_django_username,
    # Default, by value None, is the value of `OIDC_OP_EXPECTED_EMAIL_CLAIM`
    # You can also provide a lambda that takes all the claims as argument and return an email
    'OIDC_EMAIL_CLAIM': None,
    # You can also provide a lambda that takes all the claims as argument and return a firstname
    'OIDC_FIRSTNAME_CLAIM': 'given_name',
    # You can also provide a lambda that takes all the claims as argument and return a lastname
    'OIDC_LASTNAME_CLAIM': 'family_name',
    # Callable (that takes the user and the claims as arguments) to extend user with other potential additional information available in the claims
    'OIDC_EXTEND_USER': None,
    # Scramble the password on each SSO connection/renewal. If False, it will only scramble it when creating an account.
    'OIDC_UNUSABLE_PASSWORD': True,
    'OIDC_BLACKLIST_TOKEN_TIMEOUT_SECONDS': 7 * 86400,  # 7 days
    # Only used when using authorization in header:
    #   Authorization: Bearer id_token
    # This is only possible if oauth2_authcodeflow.auth.BearerAuthenticationBackend has been added to AUTHENTICATION_BACKENDS config list.
    'OIDC_AUTHORIZATION_HEADER_PREFIX': 'Bearer',
    # The RefreshAccessTokenMiddleware and RefreshSessionMiddleware will use this list bypass auth checks.
    # You should include at least any failure/error urls in it.
    'OIDC_MIDDLEWARE_NO_AUTH_URL_PATTERNS': [],
    # The RefreshAccessTokenMiddleware and RefreshSessionMiddleware will use this list to answer JSON response in case of refresh failure.
    # Expected list of regexp URL patterns.
    'OIDC_MIDDLEWARE_API_URL_PATTERNS': ['^/api/'],
    'OIDC_MIDDLEWARE_SESSION_TIMEOUT_SECONDS': 7 * 86400,  # 7 days
}
# settings that may be in dotted string import notation and should be transformed in a lazy way.
IMPORT_STRINGS = [
    'OIDC_VIEW_AUTHENTICATE',
    'OIDC_VIEW_CALLBACK',
    'OIDC_VIEW_LOGOUT',
    'OIDC_VIEW_TOTAL_LOGOUT',
    'OIDC_VIEW_LOGOUT_BY_OP',
    'OIDC_DJANGO_USERNAME_FUNC',
]


class Settings:
    """
    A settings object, that allows settings to be accessed as properties.
    Any setting with dotted string import paths will be resolved to the callable.
    """
    def __init__(self, defaults=None, import_strings=None):
        self.defaults = defaults or DEFAULTS
        self.import_strings = import_strings or IMPORT_STRINGS

    def __getattr__(self, attr):
        if hasattr(dj_settings, attr):
            val = getattr(dj_settings, attr)
        else:
            if attr not in self.defaults:
                raise ImproperlyConfigured(f"Invalid setting: '{attr}'")
            # Fall back to defaults
            val = self.defaults[attr]
        if val is ImproperlyConfigured:
            raise val(f"Setting '{attr}' not found, it should be defined")
        # Coerce import strings into classes
        if attr in self.import_strings:
            val = import_string_if_not_func(val, attr)
        # Cache the result
        setattr(self, attr, val)
        return val


settings = Settings()
