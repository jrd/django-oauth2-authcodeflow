import json
from base64 import urlsafe_b64encode
from hashlib import sha256
from importlib import import_module
from logging import (
    debug,
    warning,
)
from typing import (
    Dict,
    List,
    Optional,
    Tuple,
    Type,
)
from urllib.parse import parse_qs

from django.contrib import auth
from django.contrib.sessions.backends.base import SessionBase
from django.core.exceptions import SuspiciousOperation
from django.http import (
    HttpResponse,
    HttpResponseBadRequest,
    HttpResponseRedirect,
)
from django.http.request import HttpRequest
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.utils.decorators import method_decorator
from django.utils.http import urlencode
from django.views.decorators.cache import never_cache
from django.views.generic import View
from jose import jwt
from jose.exceptions import JWTError

from .conf import (
    constants,
    settings,
)
from .models import BlacklistedToken
from .utils import OIDCUrlsMixin


class BadRequestException(Exception):
    def __str__(self) -> str:
        return str(self.args[0])


class CacheBaseView(View, OIDCUrlsMixin):
    @method_decorator(never_cache)
    def dispatch(self, request: HttpRequest, *args, **kwargs) -> HttpResponse:
        self._set_cache(request)
        response = super().dispatch(request, *args, **kwargs)
        response['Pragma'] = 'no-cache'  # HTTP 1.0 compat
        response['Expires'] = '0'  # for proxies
        return response

    def _set_cache(self, request: HttpRequest) -> None:
        for key, value in self.get_oidc_urls(request.session).items():
            request.session[key] = value

    def _clear_cache(self, request: HttpRequest) -> None:
        for conf in dir(constants):
            value = getattr(constants, conf)
            if conf.startswith('SESSION') and value in request.session:
                del request.session[value]
        request.session.save()


class UrlParamsMixin:
    def get_url_with_params(self, _url: str, **params: str) -> str:
        return f"{_url}?{urlencode(params)}" if params else _url


class AuthenticateView(CacheBaseView, UrlParamsMixin):
    """
    Ask the OP for a temporary code (auth code flow),
    Using at least the openid scope (OIDC).
    Ends with a redirect.
    """
    http_method_names = ['get']

    def get_from_cli(self, request: HttpRequest) -> bool:
        return bool(request.GET.get(constants.OIDC_FROM_CLI_QUERY_STRING))

    def get_next_and_failure_url(self, request: HttpRequest, from_cli: bool) -> Tuple[str, str]:
        if from_cli:
            next_url = '/FROM_CLI_OK'
            failure_url = '/FROM_CLI_FAIL'
            request.session.save()  # ensure request.session.session_key is not None
        else:
            next_url = request.GET.get(settings.OIDC_REDIRECT_OK_FIELD_NAME, '/')
            failure_url = request.GET.get(settings.OIDC_REDIRECT_ERROR_FIELD_NAME, '/')
        if not next_url:
            raise SuspiciousOperation(f"{settings.OIDC_REDIRECT_OK_FIELD_NAME} parameter is required")
        if not failure_url:
            raise SuspiciousOperation(f"{settings.OIDC_REDIRECT_ERROR_FIELD_NAME} parameter is required")
        return next_url, failure_url

    def get_claims_parameter(self, request: HttpRequest) -> Optional[Dict[str, str]]:
        if request.session.get(constants.OIDC_CLAIMS_PARAMETER_SUPPORTED, False):
            claims_parameter = {}
            if settings.OIDC_RP_USERINFO_CLAIMS:
                claims_parameter['userinfo'] = settings.OIDC_RP_USERINFO_CLAIMS
            if settings.OIDC_RP_TOKEN_CLAIMS:
                claims_parameter['id_token'] = settings.OIDC_RP_TOKEN_CLAIMS
            if claims_parameter:
                return claims_parameter
        return None

    def fill_params_for_pkce(self, request: HttpRequest, session_updates: Dict[str, str], auth_params: Dict[str, str], from_cli: bool) -> None:
        code_verifier = get_random_string(length=100, allowed_chars='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~')
        code_challenge = urlsafe_b64encode(sha256(code_verifier.encode('ascii')).digest()).decode('ascii').strip('=')
        auth_params.update(code_challenge_method='S256', code_challenge=code_challenge)
        session_updates[constants.SESSION_CHALLENGE] = code_verifier

    def fill_params_without_pkce(self, request: HttpRequest, session_updates: Dict[str, str], auth_params: Dict[str, str], from_cli: bool) -> None:
        if from_cli:
            state = jwt.encode({'session_key': request.session.session_key}, settings.SECRET_KEY, algorithm='HS256')
        else:
            state = get_random_string(settings.OIDC_RANDOM_SIZE)
        nonce = get_random_string(settings.OIDC_RANDOM_SIZE)
        auth_params.update(state=state, nonce=nonce)
        session_updates[constants.SESSION_STATE] = state
        session_updates[constants.SESSION_NONCE] = nonce

    def get_auth_params(self, request: HttpRequest, from_cli: bool, use_pkce: bool, scopes: List[str]) -> Tuple[Dict[str, str], Dict[str, str]]:
        session_updates: Dict[str, str] = {}
        auth_params: Dict[str, str] = {
            'response_type': 'code',
            'client_id': settings.OIDC_RP_CLIENT_ID,
            'scope': ' '.join(scopes),
            'redirect_uri': request.build_absolute_uri(reverse(constants.OIDC_URL_CALLBACK_NAME)),
        }
        claims_parameter = self.get_claims_parameter(request)
        if claims_parameter:
            auth_params['claims'] = json.dumps(claims_parameter)
        if 'offline_access' in scopes or settings.OIDC_RP_FORCE_CONSENT_PROMPT:
            auth_params['prompt'] = 'consent'
        if use_pkce:
            self.fill_params_for_pkce(request, session_updates, auth_params, from_cli)
        else:
            self.fill_params_without_pkce(request, session_updates, auth_params, from_cli)
        return session_updates, auth_params

    def get(self, request: HttpRequest) -> HttpResponse:
        from_cli = self.get_from_cli(request)
        next_url, failure_url = self.get_next_and_failure_url(request, from_cli)
        request.session[constants.SESSION_NEXT_URL] = next_url
        request.session[constants.SESSION_FAIL_URL] = failure_url
        url = request.session[constants.SESSION_OP_AUTHORIZATION_URL]
        exclude_scopes = ['offline_access'] if from_cli else []
        scopes = [scope for scope in settings.OIDC_RP_SCOPES if scope not in exclude_scopes]
        use_pkce = not from_cli and settings.OIDC_RP_USE_PKCE
        session_updates, auth_params = self.get_auth_params(request, from_cli, use_pkce, scopes)
        for key, value in session_updates.items():
            request.session[key] = value
        request.session.save()
        redirect_url = self.get_url_with_params(url, **auth_params)
        if from_cli:
            # special cases when the request comes from CLI,
            # a redirect will not be usefull, only the redirect location is required.
            return HttpResponse(f"Go to:\n{redirect_url}\n", content_type='text/plain')
        else:
            return HttpResponseRedirect(redirect_url)


class CallbackView(CacheBaseView, UrlParamsMixin):
    """
    Callback from the OP.
    Ends with a redirect.
    """
    http_method_names = ['get']
    SessionStore: Type[SessionBase]

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.SessionStore = import_module(settings.SESSION_ENGINE).SessionStore

    def get_from_cli(self, request: HttpRequest) -> bool:
        if 'state' in request.GET:
            state = request.GET['state']
            try:
                jwt.get_unverified_header(state)
                return True
            except JWTError:
                return False
        else:
            return False

    def prepare_session_and_get_state(self, request: HttpRequest, from_cli: bool) -> Optional[str]:
        state = request.GET.get('state', None)
        if state and from_cli:
            debug("Try to get the session from the state parameter instead of using cookies")
            try:
                # as called from CLI initialy, the session will not be in the cookie.
                # hence, load the session from the session_key stored in the jwt state
                session_key = jwt.decode(state, settings.SECRET_KEY, 'HS256')['session_key']
                old_session_items = request.session.items()
                request.session = self.SessionStore(session_key)
                for key, value in old_session_items:
                    request.session.setdefault(key, value)
                debug(f"request.session replaced with request.session.session_key={request.session.session_key}")
            except (JWTError, KeyError):
                raise BadRequestException("state appears to be a JWT but the signature failed")
        return state

    def get_next_and_failure_url(self, request: HttpRequest, from_cli: bool) -> Tuple[str, str]:
        next_url = request.session.get(constants.SESSION_NEXT_URL)
        failure_url = request.session.get(constants.SESSION_FAIL_URL)
        if not next_url or not failure_url:
            raise BadRequestException(f"{constants.SESSION_NEXT_URL} and {constants.SESSION_FAIL_URL} session parameters should be filled")
        return next_url, failure_url

    def get_redirect_url(self, request: HttpRequest, use_pkce: bool, from_cli: bool, state: Optional[str], next_url: str, failure_url: str) -> str:
        if request.GET.get('error'):
            warning(request.GET['error'])
            # Make sure the user doesn't get to continue to be logged in in Django
            if request.user.is_authenticated:
                auth.logout(request)
            self._clear_cache(request)
            return self.get_url_with_params(failure_url, error=request.GET['error'])
        elif constants.SESSION_LOGOUT_STATE in request.session and state:
            return self.logout_callback(request, next_url, failure_url)
        elif 'code' in request.GET and settings.OIDC_RP_USE_PKCE or state:
            return self.auth_callback(request, next_url, failure_url, use_pkce)
        else:
            return self.get_url_with_params(failure_url, error="Unknown OIDC callback")

    def build_response_from_cli(self, request: HttpRequest, url: str) -> HttpResponse:
        """
        Special cases when the callback comes from a request initiated from CLI,
        a redirect will not be usefull, only the header is required or a http 400 with the error message.
        """
        if not url.startswith('/FROM_CLI_OK'):
            error_message = next(iter(parse_qs(url.split('?', 1)[1] if '?' in url else '').get('error', [])), '')
            raise BadRequestException(f"Error: {error_message}")
        authorization_prefix = settings.OIDC_AUTHORIZATION_HEADER_PREFIX
        id_token = request.session[constants.SESSION_ID_TOKEN]
        return HttpResponse(f"Header:\n  Authorization: {authorization_prefix} {id_token}\n", content_type='text/plain')

    def build_response_from_http(self, request: HttpRequest, url: str) -> HttpResponse:
        return HttpResponseRedirect(url)

    def build_response(self, request: HttpRequest, from_cli: bool, url: str) -> HttpResponse:
        request.session.save()
        if from_cli:
            return self.build_response_from_cli(request, url)
        else:
            return self.build_response_from_http(request, url)

    def get(self, request: HttpRequest) -> HttpResponse:
        debug(f"request.session.session_key={request.session.session_key}, request.session.keys()={request.session.keys()}")
        from_cli = self.get_from_cli(request)
        try:
            state = self.prepare_session_and_get_state(request, from_cli)
            next_url, failure_url = self.get_next_and_failure_url(request, from_cli)
            use_pkce = not from_cli and settings.OIDC_RP_USE_PKCE
            url = self.get_redirect_url(request, use_pkce, from_cli, state, next_url, failure_url)
            return self.build_response(request, from_cli, url)
        except BadRequestException as e:
            return HttpResponseBadRequest(str(e).encode('utf8'))

    def extract_auth_callback_params_with_pkce(self, request: HttpRequest) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        session_challenge = request.session.pop(constants.SESSION_CHALLENGE, None)
        if not session_challenge:
            raise SuspiciousOperation('OIDC callback: challenge not found in session')
        return None, None, session_challenge

    def extract_auth_callback_params_without_pkce(self, request: HttpRequest) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        session_state = request.session.pop(constants.SESSION_STATE, None)
        if not session_state:
            raise SuspiciousOperation('OIDC callback: state not found in session')
        state = request.GET.get('state', '')
        if state != session_state:
            raise SuspiciousOperation('OIDC callback: state values do not match')
        session_nonce = request.session.pop(constants.SESSION_NONCE, None)
        if not session_nonce:
            raise SuspiciousOperation('OIDC callback: nonce not found in session')
        return state, session_nonce, None

    def extract_auth_callback_params(self, request: HttpRequest, use_pkce: bool) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        if use_pkce:
            return self.extract_auth_callback_params_with_pkce(request)
        else:
            return self.extract_auth_callback_params_without_pkce(request)

    def auth_callback(self, request: HttpRequest, next_url: str, failure_url: str, use_pkce: bool) -> str:
        try:
            code = request.GET['code']
            state, session_nonce, session_challenge = self.extract_auth_callback_params(request, use_pkce)
            user = auth.authenticate(request, use_pkce=use_pkce, code=code, state=state, nonce=session_nonce, code_verifier=session_challenge)
            if user and user.is_active:
                # keep old session items as auth.login will probably flush the session
                old_session_items = request.session.items()
                auth.login(request, user)
                for key, value in old_session_items:
                    request.session.setdefault(key, value)
                return next_url
            else:
                return self.get_url_with_params(failure_url, error="OIDC authent callback, no user error")
        except Exception as e:
            warning(repr(e))
            return self.get_url_with_params(failure_url, error=str(e))

    def logout_callback(self, request: HttpRequest, next_url: str, failure_url: str) -> str:
        try:
            state = request.GET['state']
            session_state = request.session.get(constants.SESSION_LOGOUT_STATE)
            if state == session_state:
                if request.user.is_authenticated:
                    auth.logout(request)
                self._clear_cache(request)
                return next_url
            else:
                request.session.pop(constants.SESSION_LOGOUT_STATE, None)
                request.session.save()
                return self.get_url_with_params(failure_url, error="OIDC logout callback, bad state error")
        except Exception as e:
            warning(repr(e))
            return self.get_url_with_params(failure_url, error=str(e))


class LogoutView(CacheBaseView, UrlParamsMixin):
    """
    Logout user from the application, called by RP user-agent.
    """
    http_method_names = ['get']

    def get_next_and_failure_url(self, request: HttpRequest) -> Tuple[str, str]:
        next_url = request.GET.get(settings.OIDC_REDIRECT_OK_FIELD_NAME)
        failure_url = request.GET.get(settings.OIDC_REDIRECT_ERROR_FIELD_NAME)
        if not next_url:
            raise BadRequestException(f"{settings.OIDC_REDIRECT_OK_FIELD_NAME} parameter is required")
        if not failure_url:
            raise BadRequestException(f"{settings.OIDC_REDIRECT_ERROR_FIELD_NAME} parameter is required")
        return next_url, failure_url

    def get(self, request: HttpRequest) -> HttpResponse:
        try:
            next_url, failure_url = self.get_next_and_failure_url(request)
            if constants.SESSION_ID_TOKEN not in request.session:
                raise ValueError("id_token is missing from the session, cannot logout")
            id_token = request.session[constants.SESSION_ID_TOKEN]
            return self.logout(request, id_token, next_url, failure_url)
        except BadRequestException as e:
            return HttpResponseBadRequest(str(e).encode('utf8'))
        except Exception as e:
            return HttpResponseRedirect(self.get_url_with_params(failure_url, error=str(e)))

    def logout(self, request: HttpRequest, id_token: str, next_url: str, failure_url: str) -> HttpResponse:
        BlacklistedToken.blacklist(id_token)
        self._clear_cache(request)
        if request.user.is_authenticated:
            auth.logout(request)
        return HttpResponseRedirect(next_url)


class TotalLogoutView(LogoutView, UrlParamsMixin):
    """
    Logout user from the application, the OP and any application connected to the OP, called by RP user-agent.
    """
    def logout(self, request: HttpRequest, id_token: str, next_url: str, failure_url: str) -> HttpResponse:
        BlacklistedToken.blacklist(id_token)
        end_session_url = request.session.get(constants.SESSION_OP_END_SESSION_URL)
        if settings.OIDC_OP_TOTAL_LOGOUT and end_session_url:
            state = get_random_string(settings.OIDC_RANDOM_SIZE)
            logout_params = {
                'id_token_hint': id_token,
                'post_logout_redirect_uri': request.build_absolute_uri(reverse(constants.OIDC_URL_CALLBACK_NAME)),
                'state': state,
            }
            self._clear_cache(request)
            request.session[constants.SESSION_NEXT_URL] = next_url
            request.session[constants.SESSION_FAIL_URL] = failure_url
            # id token needs to go back into session because the OP may call the LogoutByOPView on logout
            # and LogoutByOPView needs the id token
            request.session[constants.SESSION_ID_TOKEN] = id_token
            request.session[constants.SESSION_LOGOUT_STATE] = state
            request.session.save()
            redirect_url = self.get_url_with_params(end_session_url, **logout_params)
            return HttpResponseRedirect(redirect_url)
        else:
            return super().logout(request, id_token, next_url, failure_url)


class LogoutByOPView(CacheBaseView):
    """
    Logout user, called by OP.
    """
    http_method_names = ['get']

    def get(self, request: HttpRequest) -> HttpResponse:
        try:
            sid = request.GET.get('sid')
            if not sid:
                raise ValueError("sid parameter is required for logout by OP")
            id_token = request.session.get(constants.SESSION_ID_TOKEN)
            if id_token:
                claims = jwt.get_unverified_claims(id_token)
                if claims.get('sid', sid) != sid:
                    raise ValueError("bad sid parameter")
                BlacklistedToken.blacklist(id_token)
            else:
                raise ValueError("missing id_token session parameter")
            return HttpResponse()
        except Exception as e:
            warning(repr(e))
            return HttpResponseBadRequest(str(e).encode('utf8'))
