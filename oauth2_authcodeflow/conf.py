from base64 import urlsafe_b64encode
from hashlib import sha1
from types import FunctionType
from typing import (
    Any,
    Callable,
    Dict,
    Optional,
    Set,
    Tuple,
)

from django.conf import settings as dj_settings
from django.core.exceptions import ImproperlyConfigured
from django.core.signals import setting_changed
from django.utils.module_loading import import_string

from . import constants


def import_string_as_func(value: str, attr: str) -> Callable:
    try:
        return import_string(value)
    except ImportError as e:
        raise ImportError(f"Could not import '{value}' for API setting '{attr}'. {e.__class__.__name__}: {e}.")


def get_default_django_username(claims: Dict) -> str:
    """base64 encode of the email hash (sha1)"""
    return urlsafe_b64encode(
        sha1(claims.get('email', '').encode('utf8')).digest()
    ).decode('ascii').rstrip('=')


DEFAULTS: Dict[str, Tuple[Any, Any]] = {
    'OIDC_VIEW_AUTHENTICATE': (type, f'{__package__}.views.AuthenticateView'),
    'OIDC_VIEW_CALLBACK': (type, f'{__package__}.views.CallbackView'),
    'OIDC_VIEW_LOGOUT': (type, f'{__package__}.views.LogoutView'),
    'OIDC_VIEW_TOTAL_LOGOUT': (type, f'{__package__}.views.TotalLogoutView'),
    'OIDC_VIEW_LOGOUT_BY_OP': (type, f'{__package__}.views.LogoutByOPView'),
    # URL of your OpenID connect Provider discovery document url (recommended).
    # If you provide this, the following configs will be ignored:
    # - `OIDC_OP_AUTHORIZATION_URL`
    # - `OIDC_OP_TOKEN_URL`
    # - `OIDC_OP_USERINFO_URL`
    # - `OIDC_OP_JWKS_URL`
    'OIDC_OP_DISCOVERY_DOCUMENT_URL': (str, None),
    # URL of your OpenID connect Provider authorization endpoint (not recommended, `OIDC_OP_DISCOVERY_DOCUMENT_URL` is preferred).
    'OIDC_OP_AUTHORIZATION_URL': (str, None),
    # URL of your OpenID connect Provider token endpoint (not recommended, `OIDC_OP_DISCOVERY_DOCUMENT_URL` is preferred).
    'OIDC_OP_TOKEN_URL': (str, None),
    # URL of your OpenID connect Provider userinfo endpoint (not recommended, `OIDC_OP_DISCOVERY_DOCUMENT_URL` is preferred).
    'OIDC_OP_USERINFO_URL': (str, None),
    # URL of your OpenId connect Provider endpoint to get public signing keys (in `PEM` or `DER` format).
    # This is used to verify the `id_token`.
    # This is not recommended to provide this url here but rather use `OIDC_OP_DISCOVERY_DOCUMENT_URL` config.
    'OIDC_OP_JWKS_URL': (str, None),
    # URL of your OpenID connect Provider end session endpoint (not recommended, `OIDC_OP_DISCOVERY_DOCUMENT_URL` is preferred).
    'OIDC_OP_END_SESSION_URL': (str, None),
    # Fetch user info on login or not.
    'OIDC_OP_FETCH_USER_INFO': (bool, True),
    # Do a call to total logout will call the OP for a logout. Default true.
    # Be careful, some OP will not follow the RFC and will not allow the user to NOT logout all connected apps.
    # Azure is such a bad example.
    'OIDC_OP_TOTAL_LOGOUT': (bool, True),
    # expected email key.
    'OIDC_OP_EXPECTED_EMAIL_CLAIM': (str, 'email'),
    # `OIDC_OP_EXPECTED_EMAIL_CLAIM` value is automatically included in this list.
    'OIDC_OP_EXPECTED_CLAIMS': (list, []),
    # OpenID Connect client ID provided for your Relaying Party/client by your OpenIdConnect Provider
    'OIDC_RP_CLIENT_ID': (str, ImproperlyConfigured),
    # OpenID Connect client secret provided for your Relaying Party/client by your OpenIdConnect Provider
    'OIDC_RP_CLIENT_SECRET': (str, ImproperlyConfigured),
    # `PKCE` improve security, disable it only if your provider cannot handle it.
    'OIDC_RP_USE_PKCE': (bool, True),
    # Force to ask for consent on login, even if `offline_access` is not in scopes
    'OIDC_RP_FORCE_CONSENT_PROMPT': (bool, False),
    # The OpenID Connect scopes to request during login.
    # The scopes could be usefull later to get access to other ressources.
    # `openid` must be in the list.
    # You can also include the `email` scope to ensure that the email field will be in the claims (recommended).
    # You can also include the `profile` scope to get more (like names, …) info in the `id_token` (recommended).
    # You can also get a `refresh_token` by specifying the `offline_access` scope.
    'OIDC_RP_SCOPES': (list, ['openid', 'email', 'profile', 'offline_access']),
    # The OpenID Connect list of individual claims to request (optional).
    # OpenID Connect authorization request parameter `userinfo` dict to add to id token request.
    'OIDC_RP_USERINFO_CLAIMS': (dict, None),
    # OpenID Connect authorization request parameter `id_token` dict to add to id token request.
    'OIDC_RP_TOKEN_CLAIMS': (dict, None),
    # Sets the algorithms the IdP may use to sign ID tokens.
    # Typical values ar 'HS256' (no key required) and 'RS256' (public key required)
    # The public keys might be defined in `OIDC_RP_IDP_SIGN_KEY` or deduced using the `OIDC_OP_JWKS_URL` config.
    'OIDC_RP_SIGN_ALGOS_ALLOWED': (list, ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512']),
    # Public RSA used to verify signatures. Overrides keys from JWKS endpoint.
    # Should be in PEM or DER format.
    'OIDC_RP_IDP_SIGN_KEY': (bytes, None),
    # Enables or disables automatic user creation during authentication
    'OIDC_CREATE_USER': (bool, True),
    # Sets the length of the random string used in the OAuth2 protocol.
    'OIDC_RANDOM_SIZE': (int, 32),
    # Defines a proxy for all requests to the OpenID Connect provider (fetch JWS, retrieve JWT tokens, Userinfo Endpoint).
    # The default is set to None which means the library will not use a proxy and connect directly.
    # For configuring a proxy check the Python requests documentation: https://requests.readthedocs.io/en/master/user/advanced/#proxies
    'OIDC_PROXY': (dict, None),
    # Defines a timeout for all requests to the OpenID Connect provider (fetch JWS, retrieve JWT tokens, Userinfo Endpoint).
    # The default is set to None which means the library will wait indefinitely.
    # The time can be defined as seconds (integer).
    # More information about possible configuration values, see Python requests: https://requests.readthedocs.io/en/master/user/quickstart/#timeouts
    'OIDC_TIMEOUT': (int, None),
    # Sets the GET parameter that is being used to define the redirect URL after succesful authentication
    'OIDC_REDIRECT_OK_FIELD_NAME': (str, 'next'),
    # Sets the GET parameter that is being used to define the redirect URL after failed authentication
    'OIDC_REDIRECT_ERROR_FIELD_NAME': (str, 'fail'),
    # Function or dotted path to a function that compute the django username based on claims.
    # The username should be unique for this app.
    # The default is to use a base64 encode of the email hash (sha1).
    'OIDC_DJANGO_USERNAME_FUNC': (FunctionType, get_default_django_username),
    # Default, by value None, is the value of `OIDC_OP_EXPECTED_EMAIL_CLAIM`
    # You can also provide a lambda that takes all the claims as argument and return an email
    'OIDC_EMAIL_CLAIM': ((str, FunctionType), None),
    # You can also provide a lambda that takes all the claims as argument and return a firstname
    'OIDC_FIRSTNAME_CLAIM': ((str, FunctionType), 'given_name'),
    # You can also provide a lambda that takes all the claims as argument and return a lastname
    'OIDC_LASTNAME_CLAIM': ((str, FunctionType), 'family_name'),
    # Callable (that takes the user, the claims and optionaly the request and access_token as arguments)
    # to extend user with other potential additional information available in the claims or from another request
    # You can also specify a dotted path to a callable
    'OIDC_EXTEND_USER': (FunctionType, None),
    # Scramble the password on each SSO connection/renewal. If False, it will only scramble it when creating an account.
    'OIDC_UNUSABLE_PASSWORD': (bool, True),
    'OIDC_BLACKLIST_TOKEN_TIMEOUT_SECONDS': (int, 7 * 86400),  # 7 days
    # Only used when using authorization in header:
    #   Authorization: Bearer id_token
    # This is only possible if oauth2_authcodeflow.auth.BearerAuthenticationBackend has been added to AUTHENTICATION_BACKENDS config list.
    'OIDC_AUTHORIZATION_HEADER_PREFIX': (str, 'Bearer'),
    # The RefreshAccessTokenMiddleware and RefreshSessionMiddleware will use this list to bypass auth checks.
    # Any url listed here will not be tried to be authenticated using Auth Code Flow.
    # You should include at least any failure/error or admin urls in it.
    'OIDC_MIDDLEWARE_NO_AUTH_URL_PATTERNS': (list, []),
    # Redirect to login page if not authenticated when using LoginRequiredMiddleware
    'OIDC_MIDDLEWARE_LOGIN_REQUIRED_REDIRECT': (bool, True),
    # The RefreshAccessTokenMiddleware and RefreshSessionMiddleware will use this list to answer JSON response in case of refresh failure.
    # Expected list of regexp URL patterns.
    'OIDC_MIDDLEWARE_API_URL_PATTERNS': (list, ['^/api/']),
    'OIDC_MIDDLEWARE_SESSION_TIMEOUT_SECONDS': (int, 7 * 86400),  # 7 days
}


class Settings:
    """
    A settings object, that allows settings to be accessed as properties.
    """
    defaults: Dict[str, Tuple[Any, Any]]

    def __init__(self, defaults: Optional[Dict[str, Tuple[Any, Any]]] = None) -> None:
        self.defaults = defaults or DEFAULTS
        self._cache: Set[str] = set()
        setting_changed.connect(self.reload)

    def __getattr__(self, attr: str) -> Any:
        atype, def_val = self.defaults.get(attr, (None, None))
        val = getattr(dj_settings, attr, def_val)
        if atype is None:  # other setting
            atype = type(val),
        elif not isinstance(atype, tuple):
            atype = atype,
        val = self._check_type_and_get_value(attr, val, atype)
        # cache the result
        self._cache.add(attr)
        setattr(self, attr, val)
        return val

    def _check_type_and_get_value(self, attr: str, val: Any, atype: tuple) -> Any:
        if (FunctionType in atype or type in atype) and isinstance(val, str) and '.' in val:
            val = import_string_as_func(val, attr)  # dotted strings to function
        if val is ImproperlyConfigured:
            raise ImproperlyConfigured(f"Setting '{attr}' not found, it should be defined")
        if val is not None and not isinstance(val, atype):
            raise ImproperlyConfigured(f"Invalid setting: '{attr}' should be of type {', '.join(map(str, atype))} and is of type {type(val)}")
        return val

    def reload(self, *args, **kwargs) -> None:
        attr = str(kwargs.get('setting'))
        # hasattr cannot be used because it relies on getattr and __getattr__, so use the _cache
        if attr in self._cache:
            self._cache.remove(attr)
        try:
            delattr(self, attr)
        except AttributeError:
            pass


settings = Settings()


__all__ = [
    'Settings',
    'constants',
    'get_default_django_username',
    'import_string_as_func',
    'settings',
]
