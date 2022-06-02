from logging import debug, error
from re import search
from time import gmtime, strftime, time
from urllib.parse import urlencode

from django.contrib.auth import BACKEND_SESSION_KEY
from django.contrib.sessions.models import Session
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponseRedirect, JsonResponse
from django.urls import reverse
from django.utils.deprecation import MiddlewareMixin
from django.utils.module_loading import import_string
from requests import post as request_post

from .auth import AuthenticationBackend, BearerAuthenticationBackend
from .conf import constants, settings
from .models import BlacklistedToken


class MiddlewareException(Exception):
    def __str__(self):
        return self.args[0]


class Oauth2MiddlewareMixin(MiddlewareMixin):
    def __init__(self, get_response, token_type, check_function):
        self.token_type = token_type
        self.check_function = check_function
        self.exempt_urls = tuple(
            f'^{reverse(url)}' for url in (
                constants.OIDC_URL_AUTHENTICATION_NAME,
                constants.OIDC_URL_CALLBACK_NAME,
                constants.OIDC_URL_LOGOUT_NAME,
                constants.OIDC_URL_TOTAL_LOGOUT_NAME,
                constants.OIDC_URL_LOGOUT_BY_OP_NAME,
            )
        ) + tuple(settings.OIDC_MIDDLEWARE_NO_AUTH_URL_PATTERNS)
        debug(f"self.exempt_urls={self.exempt_urls}")
        super().__init__(get_response)

    def is_oidc_enabled(self, request):
        auth_backend = None
        backend_session = request.session.get(BACKEND_SESSION_KEY)
        if backend_session and request.user and request.user.is_authenticated:
            auth_backend = import_string(backend_session)
        return issubclass(auth_backend, AuthenticationBackend) if auth_backend else False

    def is_refreshable_url(self, request):
        """
        Takes a request and returns whether it triggers a refresh examination
        :arg HttpRequest request:
        :returns: boolean
        """
        # Do not attempt to refresh the session if the OIDC backend is not used
        is_oidc_enabled = self.is_oidc_enabled(request)
        debug(f"is_oidc_enabled={is_oidc_enabled}, request.path={request.path}, self.exempt_urls={self.exempt_urls}")
        if is_oidc_enabled:
            for url_pattern in self.exempt_urls:
                if search(url_pattern, request.path):
                    return False
            return True
        else:
            return False

    def is_api_request(self, request):
        return any(
            search(url_pattern, request.path)
            for url_pattern in settings.OIDC_MIDDLEWARE_API_URL_PATTERNS
        )

    def process_request(self, request):
        try:
            debug(f"self={self}, request.session.session_key={request.session.session_key}, request.session.keys()={request.session.keys()}")
            if constants.SESSION_ID_TOKEN in request.session:
                id_token = request.session[constants.SESSION_ID_TOKEN]
                if BlacklistedToken.is_blacklisted(id_token):
                    debug(f"token {id_token} is blacklisted")
                    raise MiddlewareException(f"token {id_token} is blacklisted")
            self.check_function(request)
            return
        except MiddlewareException as e:
            if request.method == 'GET':
                next_url = request.GET.get(settings.OIDC_REDIRECT_OK_FIELD_NAME)
                if next_url is None:
                    next_url = request.build_absolute_uri()
                failure_url = request.GET.get(settings.OIDC_REDIRECT_ERROR_FIELD_NAME)
                if failure_url is None:
                    failure_url = request.session.get(constants.SESSION_FAIL_URL, '/')
            else:
                next_url = request.session.get(constants.SESSION_NEXT_URL, '/')
                failure_url = request.session.get(constants.SESSION_FAIL_URL, '/')
            # Destroy session
            try:
                Session.objects.get(session_key=request.session.session_key).delete()
            except Session.DoesNotExist:
                pass
            if self.is_api_request(request):
                # Return JSON response
                return JsonResponse({
                    'error': str(e),
                    'token_type': self.token_type,
                }, status=401)
            else:
                # Redirect to authentication page
                return HttpResponseRedirect(reverse(constants.OIDC_URL_AUTHENTICATION_NAME) + '?' + urlencode({
                    settings.OIDC_REDIRECT_OK_FIELD_NAME: next_url,
                    settings.OIDC_REDIRECT_ERROR_FIELD_NAME: failure_url,
                }))


class RefreshAccessTokenMiddleware(Oauth2MiddlewareMixin):
    """
    Refreshes the access token with the OIDC RP after expiry seconds
    For users authenticated with the OIDC RP, verify tokens are still valid and
    if not, force the user to refresh silently.
    """
    def __init__(self, get_response):
        super().__init__(get_response, 'access_token', self.check_access_token)

    def check_access_token(self, request):
        if not self.is_refreshable_url(request):
            debug(f"{request.path} is not refreshable")
            return
        debug(f"{request.path} is refreshable")
        if constants.SESSION_REFRESH_TOKEN not in request.session:
            return
        expiration = request.session[constants.SESSION_ACCESS_EXPIRES_AT]
        now = time()
        if expiration > now:
            # The id_token is still valid, so we don't have to do anything.
            debug('access token is still valid (%s > %s)', strftime('%d/%m/%Y, %H:%M:%S', gmtime(expiration)), strftime('%d/%m/%Y, %H:%M:%S', gmtime(now)))
            return
        debug('access token has expired')
        # The access_token has expired, so we have to refresh silently.
        # Build the parameters.
        params = {
            'grant_type': 'refresh_token',
            'client_id': settings.OIDC_RP_CLIENT_ID,
            'client_secret': settings.OIDC_RP_CLIENT_SECRET,
            'refresh_token': request.session[constants.SESSION_REFRESH_TOKEN],
        }
        resp = request_post(request.session[constants.SESSION_OP_TOKEN_URL], data=params)
        if not resp:
            error(resp.text)
            raise MiddlewareException(resp.text)
        result = resp.json()
        access_token = result['access_token']
        expires_in = result['expires_in']  # in secs
        id_token = result.get('id_token', request.session[constants.SESSION_ID_TOKEN])
        refresh_token = result.get('refresh_token', request.session[constants.SESSION_REFRESH_TOKEN])
        if id_token != request.session[constants.SESSION_ID_TOKEN]:
            # blacklist old token
            BlacklistedToken.blacklist(request.session[constants.SESSION_ID_TOKEN])
        now = time()
        request.session[constants.SESSION_ID_TOKEN] = id_token
        request.session[constants.SESSION_ACCESS_TOKEN] = access_token
        request.session[constants.SESSION_ACCESS_EXPIRES_AT] = now + expires_in
        request.session[constants.SESSION_REFRESH_TOKEN] = refresh_token
        request.session.save()


class RefreshSessionMiddleware(Oauth2MiddlewareMixin):
    """
    Checks if the session expired.
    """
    def __init__(self, get_response):
        if not (10 < settings.OIDC_MIDDLEWARE_SESSION_TIMEOUT_SECONDS < settings.SESSION_COOKIE_AGE):
            raise ImproperlyConfigured("OIDC_MIDDLEWARE_SESSION_TIMEOUT_SECONDS should be less than SESSION_COOKIE_AGE and more than 10 seconds")
        super().__init__(get_response, 'refresh_token', self.check_session)

    def check_session(self, request):
        if not self.is_refreshable_url(request):
            debug(f"{request.path} is not refreshable")
            return
        debug(f"{request.path} is refreshable")
        expiration = request.session.get(constants.SESSION_EXPIRES_AT)
        if not expiration:
            msg = f"No {constants.SESSION_EXPIRES_AT} parameter in the backend session"
            debug(msg)
            raise MiddlewareException(msg)
        now = time()
        if expiration > now:
            # The session is still valid, so we don't have to do anything.
            debug('session is still valid (%s > %s)', strftime('%d/%m/%Y, %H:%M:%S', gmtime(expiration)), strftime('%d/%m/%Y, %H:%M:%S', gmtime(now)))
            return
        # The session has expired, an authentication is now required
        # Blacklist the current id token
        BlacklistedToken.blacklist(request.session[constants.SESSION_ID_TOKEN])
        msg = "Session has expired"
        debug(msg)
        raise MiddlewareException(msg)


class BearerAuthMiddleware(Oauth2MiddlewareMixin):
    """
    Inject User in request if authenticate from header.
    """
    def __init__(self, get_response):
        super().__init__(get_response, None, None)

    def process_request(self, request):
        if 'Authorization' in request.headers:
            user = BearerAuthenticationBackend().authenticate(request)
            if user:
                request.user = user
                if not request.session.session_key:
                    # ensure request.session.session_key exists
                    request.session.save()
        return
