from logging import (
    debug,
    error,
)
from re import search
from time import (
    gmtime,
    mktime,
    strftime,
)
from typing import (
    Callable,
    Optional,
    Tuple,
    Union,
)
from urllib.parse import urlencode

from django.contrib.auth import (
    BACKEND_SESSION_KEY,
    authenticate,
)
from django.contrib.sessions.models import Session
from django.core.exceptions import ImproperlyConfigured
from django.http import (
    HttpResponseRedirect,
    JsonResponse,
)
from django.http.request import HttpRequest
from django.http.response import HttpResponse
from django.urls import reverse
from django.utils.module_loading import import_string
from requests import post as request_post

from .auth import (
    AuthenticationBackend,
    BearerAuthenticationBackend,
)
from .conf import (
    constants,
    settings,
)
from .models import BlacklistedToken


class MiddlewareException(Exception):
    def __str__(self):
        return self.args[0]


GetResponseCallable = Callable[[HttpRequest], HttpResponse]
CheckFunctionCallable = Callable[[HttpRequest], None]


class Oauth2MiddlewareMixin:
    """
    Takes optionals token_type  and check_function.
    Each request call trigger a call to process_request which uses check_function to verify if oauth2 tokens are still ok.
    If not, a MiddlewareException should be raised and a redirection to login is realized or a json error returned.
    """
    get_response: GetResponseCallable
    token_type: Optional[str]
    check_function: Optional[CheckFunctionCallable]
    exempt_urls: Tuple[str, ...]

    def __init__(self, get_response: GetResponseCallable, token_type: Optional[str], check_function: Optional[CheckFunctionCallable]) -> None:
        self.get_response = get_response
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
        ) + tuple(str(p) for p in settings.OIDC_MIDDLEWARE_NO_AUTH_URL_PATTERNS)
        debug(f"self.exempt_urls={self.exempt_urls}")

    def __call__(self, request: HttpRequest) -> HttpResponse:
        response = self.process_request(request)
        return response or self.get_response(request)

    def is_oidc_enabled(self, request: HttpRequest) -> bool:
        auth_backend = None
        backend_session = request.session.get(BACKEND_SESSION_KEY)
        debug(f"backend_session={backend_session}")
        if backend_session and hasattr(request, 'user') and request.user.is_authenticated:
            auth_backend = import_string(backend_session)
        return issubclass(auth_backend, AuthenticationBackend) if auth_backend else False

    def is_refreshable_url(self, request: HttpRequest) -> bool:
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

    def check_blacklisted(self, request: HttpRequest) -> None:
        debug(f"self={self}, request.session.session_key={request.session.session_key}, request.session.keys()={request.session.keys()}")
        if constants.SESSION_ID_TOKEN in request.session:
            id_token = request.session[constants.SESSION_ID_TOKEN]
            if BlacklistedToken.is_blacklisted(id_token):
                debug(f"token {id_token} is blacklisted")
                raise MiddlewareException(f"token {id_token} is blacklisted")

    def get_next_url(self, request: HttpRequest) -> str:
        if request.method == 'GET':
            next_url = request.GET.get(settings.OIDC_REDIRECT_OK_FIELD_NAME)
            return request.build_absolute_uri() if next_url is None else next_url
        else:
            return request.session.get(constants.SESSION_NEXT_URL, '/')

    def get_failure_url(self, request: HttpRequest) -> str:
        if request.method == 'GET':
            failure_url = request.GET.get(settings.OIDC_REDIRECT_ERROR_FIELD_NAME)
            return request.session.get(constants.SESSION_FAIL_URL, '/') if failure_url is None else failure_url
        else:
            return request.session.get(constants.SESSION_FAIL_URL, '/')

    def destroy_session(self, request: HttpRequest) -> None:
        try:
            Session.objects.get(session_key=request.session.session_key).delete()
        except Session.DoesNotExist:
            pass

    def is_api_request(self, request: HttpRequest) -> bool:
        return any(
            search(url_pattern, request.path)
            for url_pattern in settings.OIDC_MIDDLEWARE_API_URL_PATTERNS
        )

    def json_401(self, request: HttpRequest, error: str) -> JsonResponse:
        """Return JSON response with Unauthorized HTTP error"""
        return JsonResponse({'error': error, 'token_type': self.token_type}, status=401)

    def re_authent(self, request: HttpRequest, next_url: str, failure_url: str) -> HttpResponseRedirect:
        """Redirect to authentication page"""
        return HttpResponseRedirect(reverse(constants.OIDC_URL_AUTHENTICATION_NAME) + '?' + urlencode({
            settings.OIDC_REDIRECT_OK_FIELD_NAME: next_url,
            settings.OIDC_REDIRECT_ERROR_FIELD_NAME: failure_url,
        }))

    def re_authent_or_401(self, request: HttpRequest, error: str, next_url: str, failure_url: str) -> Union[JsonResponse, HttpResponseRedirect]:
        if self.is_api_request(request):
            return self.json_401(request, error)
        else:
            return self.re_authent(request, next_url, failure_url)

    def process_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        try:
            self.check_blacklisted(request)
            if self.check_function:
                self.check_function(request)
            return None
        except MiddlewareException as e:
            next_url, failure_url = self.get_next_url(request), self.get_failure_url(request)
            self.destroy_session(request)
            return self.re_authent_or_401(request, str(e), next_url, failure_url)


class LoginRequiredMiddleware(Oauth2MiddlewareMixin):
    """
    Force a user to be logged-in to access all pages not listed in OIDC_MIDDLEWARE_NO_AUTH_URL_PATTERNS.
    If OIDC_MIDDLEWARE_LOGIN_REQUIRED_REDIRECT is true (default), then redirect to login page if not authenticated.
    """
    def __init__(self, get_response: GetResponseCallable) -> None:
        super().__init__(get_response, 'id_token', self.check_login_required)

    def is_login_required_for_url(self, request: HttpRequest) -> bool:
        login_required_url = False
        for url_pattern in self.exempt_urls:
            if search(url_pattern, request.path):
                break
        else:
            login_required_url = True
        return login_required_url

    def is_api_request(self, request: HttpRequest) -> bool:
        if settings.OIDC_MIDDLEWARE_LOGIN_REQUIRED_REDIRECT:
            if request.method == 'GET':
                # force redirect on GET request even if it’s a API request
                return False
            else:
                return super().is_api_request(request)
        else:
            return True

    def check_login_required(self, request: HttpRequest) -> None:
        if hasattr(request, 'user') and request.user.is_authenticated:
            debug("user is already authenticated")
            return
        if not self.is_login_required_for_url(request):
            debug(f"{request.path} does not need authenticated user")
            return
        debug(f"{request.path} needs an authenticated user")
        if constants.SESSION_ID_TOKEN not in request.session:
            try:
                user = authenticate(request)
            except Exception as e:
                raise MiddlewareException(str(e))
            if not user:
                raise MiddlewareException("id token is missing, user is not authenticated")
        else:
            debug("id token is present, authenticated user")


class RefreshAccessTokenMiddleware(Oauth2MiddlewareMixin):
    """
    Refreshes the access token with the OIDC RP after expiry seconds
    For users authenticated with the OIDC RP, verify tokens are still valid and
    if not, force the user to refresh silently.
    """
    def __init__(self, get_response: GetResponseCallable) -> None:
        super().__init__(get_response, 'access_token', self.check_access_token)

    def check_access_token(self, request: HttpRequest) -> None:
        if not self.is_refreshable_url(request):
            debug(f"{request.path} is not refreshable")
            return
        debug(f"{request.path} is refreshable")
        if constants.SESSION_REFRESH_TOKEN not in request.session:
            return
        utc_expiration = request.session[constants.SESSION_ACCESS_EXPIRES_AT]
        utc_now_struct = gmtime()
        utc_now = mktime(utc_now_struct)
        if utc_expiration > utc_now:
            # The id_token is still valid, so we don't have to do anything.
            debug(
                'access token is still valid (%s > %s)',
                strftime('%d/%m/%Y, %H:%M:%S', gmtime(utc_expiration)),
                strftime('%d/%m/%Y, %H:%M:%S', utc_now_struct),
            )
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
        request.session[constants.SESSION_ID_TOKEN] = id_token
        request.session[constants.SESSION_ACCESS_TOKEN] = access_token
        request.session[constants.SESSION_ACCESS_EXPIRES_AT] = utc_now + expires_in
        request.session[constants.SESSION_REFRESH_TOKEN] = refresh_token
        request.session.save()


class RefreshSessionMiddleware(Oauth2MiddlewareMixin):
    """
    Checks if the session expired.
    """
    MIN_SECONDS = 10

    def __init__(self, get_response: GetResponseCallable) -> None:
        if not (self.MIN_SECONDS < settings.OIDC_MIDDLEWARE_SESSION_TIMEOUT_SECONDS < settings.SESSION_COOKIE_AGE):
            raise ImproperlyConfigured(
                "OIDC_MIDDLEWARE_SESSION_TIMEOUT_SECONDS should be less than SESSION_COOKIE_AGE"
                f" and more than {self.MIN_SECONDS} seconds"
            )
        super().__init__(get_response, 'refresh_token', self.check_session)

    def check_session(self, request: HttpRequest) -> None:
        if not self.is_refreshable_url(request):
            debug(f"{request.path} is not refreshable")
            return
        debug(f"{request.path} is refreshable")
        utc_expiration = request.session.get(constants.SESSION_EXPIRES_AT)
        if not utc_expiration:
            msg = f"No {constants.SESSION_EXPIRES_AT} parameter in the backend session"
            debug(msg)
            raise MiddlewareException(msg)
        utc_now_struct = gmtime()
        utc_now = mktime(utc_now_struct)
        if utc_expiration > utc_now:
            # The session is still valid, so we don't have to do anything.
            debug(
                'session is still valid (%s > %s)',
                strftime('%d/%m/%Y, %H:%M:%S', gmtime(utc_expiration)),
                strftime('%d/%m/%Y, %H:%M:%S', utc_now_struct),
            )
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
    def __init__(self, get_response: GetResponseCallable) -> None:
        super().__init__(get_response, None, None)

    def process_request(self, request: HttpRequest) -> Optional[HttpResponse]:
        if 'Authorization' in request.headers:
            user = BearerAuthenticationBackend().authenticate(request)
            if user:
                request.user = user
                if not request.session.session_key:
                    # ensure request.session.session_key exists
                    request.session.save()
        return None
