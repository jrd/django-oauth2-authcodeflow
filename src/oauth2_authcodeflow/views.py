from base64 import urlsafe_b64encode
from hashlib import sha256
from importlib import import_module
from logging import warning, debug

from django.contrib import auth
from django.core.exceptions import SuspiciousOperation
from django.http import (
    HttpResponse,
    HttpResponseBadRequest,
    HttpResponseRedirect,
)
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.utils.decorators import method_decorator
from django.utils.http import urlencode
from django.views.decorators.cache import never_cache
from django.views.generic import View
from jose import jwt
from urllib.parse import parse_qs

from .conf import (
    constants,
    settings,
)
from .utils import OIDCUrlsMixin
from .models import BlacklistedToken


class CacheBaseView(View, OIDCUrlsMixin):
    @method_decorator(never_cache)
    def dispatch(self, request, *args, **kwargs):
        self._set_cache(request)
        response = super().dispatch(request, *args, **kwargs)
        response['Pragma'] = 'no-cache'  # HTTP 1.0 compat
        response['Expires'] = '0'  # for proxies
        return response

    def _set_cache(self, request):
        for key, value in self.get_oidc_urls(request.session).items():
            request.session[key] = value

    def _clear_cache(self, request):
        for conf in dir(constants):
            if conf.startswith('SESSION') and conf in request.session:
                del request.session[conf]
        request.session.save()


class AuthenticateView(CacheBaseView):
    """
    Ask the OP for a temporary code (auth code flow),
    Using at least the openid scope (OIDC).
    Ends with a redirect.
    """
    http_method_names = ['get']

    def get(self, request):
        from_cli = request.GET.get(constants.OIDC_FROM_CLI_QUERY_STRING)
        if from_cli:
            next_url = '/FROM_CLI_OK'
            failure_url = '/FROM_CLI_FAIL'
            request.session.save()  # ensure request.session.session_key is not None
        else:
            next_url = request.GET.get(settings.OIDC_REDIRECT_OK_FIELD_NAME)
            failure_url = request.GET.get(settings.OIDC_REDIRECT_ERROR_FIELD_NAME)
        if not next_url:
            raise SuspiciousOperation(f"{settings.OIDC_REDIRECT_OK_FIELD_NAME} parameter is required")
        if not failure_url:
            raise SuspiciousOperation(f"{settings.OIDC_REDIRECT_ERROR_FIELD_NAME} parameter is required")
        request.session[constants.SESSION_NEXT_URL] = next_url
        request.session[constants.SESSION_FAIL_URL] = failure_url
        url = request.session[constants.SESSION_OP_AUTHORIZATION_URL]
        exclude_scopes = ['offline_access'] if from_cli else []
        scopes = [scope for scope in settings.OIDC_RP_SCOPES if scope not in exclude_scopes]
        use_pkce = not from_cli and settings.OIDC_RP_USE_PKCE
        auth_params = {
            'response_type': 'code',
            'client_id': settings.OIDC_RP_CLIENT_ID,
            'scope': ' '.join(scopes),
            'redirect_uri': request.build_absolute_uri(reverse(constants.OIDC_URL_CALLBACK_NAME)),
        }
        if 'offline_access' in scopes or settings.OIDC_RP_FORCE_CONSENT_PROMPT:
            auth_params['prompt'] = 'consent'
        if use_pkce:
            code_verifier = get_random_string(length=100, allowed_chars='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~')
            code_challenge = urlsafe_b64encode(sha256(code_verifier.encode('ascii')).digest()).decode('ascii').strip('=')
            auth_params.update({
                'code_challenge_method': 'S256',
                'code_challenge': code_challenge,
            })
            request.session[constants.SESSION_CHALLENGE] = code_verifier
        else:
            if from_cli:
                state = jwt.encode({'session_key': request.session.session_key}, settings.SECRET_KEY, algorithm='HS256')
            else:
                state = get_random_string(settings.OIDC_RANDOM_SIZE)
            nonce = get_random_string(settings.OIDC_RANDOM_SIZE)
            auth_params.update({
                'state': state,
                'nonce': nonce,
            })
            request.session[constants.SESSION_STATE] = state
            request.session[constants.SESSION_NONCE] = nonce
        request.session.save()
        redirect_url = f'{url}?{urlencode(auth_params)}'
        if from_cli:
            # special cases when the request comes from CLI,
            # a redirect will not be usefull, only the redirect location is required.
            return HttpResponse(f"Go to:\n{redirect_url}\n", content_type='text/plain')
        else:
            return HttpResponseRedirect(redirect_url)


class CallbackView(CacheBaseView):
    """
    Callback from the OP.
    Ends with a redirect.
    """
    http_method_names = ['get']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.SessionStore = import_module(settings.SESSION_ENGINE).SessionStore

    def get(self, request):
        debug(f"{request.session.session_key=}, {request.session.keys()=}")
        if 'state' in request.GET:
            state = request.GET['state']
            try:
                jwt.get_unverified_header(state)
                from_cli = True
            except jwt.JWTError:
                from_cli = False
            if from_cli:
                debug("Try to get the session from the state parameter instead of using cookies")
                try:
                    # as called from CLI initialy, the session will not be in the cookie.
                    # hence, load the session from the session_key stored in the jwt state
                    session_key = jwt.decode(state, settings.SECRET_KEY, 'HS256')['session_key']
                    old_session_items = request.session.items()
                    request.session = self.SessionStore(session_key)
                    for key, value in old_session_items:
                        if key not in request.session:
                            request.session[key] = value
                    debug(f"request.session replaced with {request.session.session_key=}")
                except (jwt.JWTError, KeyError):
                    return HttpResponseBadRequest("state appears to be a JWT but the signature failed".encode('utf8'))
        else:
            from_cli = False
        next_url = request.session.get(constants.SESSION_NEXT_URL)
        failure_url = request.session.get(constants.SESSION_FAIL_URL)
        use_pkce = not from_cli and settings.OIDC_RP_USE_PKCE
        if not next_url or not failure_url:
            return HttpResponseBadRequest(f"{constants.SESSION_NEXT_URL} and {constants.SESSION_FAIL_URL} session parameters should be filled".encode('utf8'))
        if request.GET.get('error'):
            warning(request.GET['error'])
            # Make sure the user doesn't get to continue to be logged in in Django
            if request.user.is_authenticated:
                auth.logout(request)
            self._clear_cache()
            url = failure_url + '?' + urlencode({'error': request.GET['error']})
        elif all((
            'code' in request.GET,
            settings.OIDC_RP_USE_PKCE or 'state' in request.GET,
        )):
            url = self.auth_callback(request, next_url, failure_url, use_pkce)
        elif all((
            constants.SESSION_LOGOUT_STATE in request.session,
            'state' in request.GET,
        )):
            url = self.logout_callback(request, next_url, failure_url)
        else:
            url = failure_url + '?' + urlencode({'error': 'Unknown OIDC callback'})
        request.session.save()
        if from_cli:
            # special cases when the callback comes from a request initiated from CLI,
            # a redirect will not be usefull, only the header is required or a http 400 with the error message.
            if url.startswith('/FROM_CLI_OK'):
                authorization_prefix = settings.OIDC_AUTHORIZATION_HEADER_PREFIX
                id_token = request.session[constants.SESSION_ID_TOKEN]
                return HttpResponse(f"Header:\n  Authorization: {authorization_prefix} {id_token}\n", content_type='text/plain')
            else:
                error_message = next(iter(parse_qs(url.split('?', 1)[1] if '?' in url else '').get('error', [])), '')
                return HttpResponseBadRequest(f"Error: {error_message}")
        else:
            return HttpResponseRedirect(url)

    def auth_callback(self, request, next_url: str, failure_url: str, use_pkce: bool) -> str:
        url = failure_url
        try:
            code = request.GET['code']
            if use_pkce:
                state = None
                session_nonce = None
                session_challenge = request.session.pop(constants.SESSION_CHALLENGE, None)
                if not session_challenge:
                    raise SuspiciousOperation('OIDC callback: challenge not found in session')
            else:
                session_state = request.session.pop(constants.SESSION_STATE, None)
                if not session_state:
                    raise SuspiciousOperation('OIDC callback: state not found in session')
                state = request.GET['state']
                if state != session_state:
                    raise SuspiciousOperation('OIDC callback: state values do not match')
                session_nonce = request.session.pop(constants.SESSION_NONCE, None)
                if not session_nonce:
                    raise SuspiciousOperation('OIDC callback: nonce not found in session')
                session_challenge = None
            user = auth.authenticate(request, use_pkce=use_pkce, code=code, state=state, nonce=session_nonce, code_verifier=session_challenge)
            if user and user.is_active:
                # keep old session items as auth.login will probably flush the session
                old_session_items = request.session.items()
                auth.login(request, user)
                for key, value in old_session_items:
                    if key not in request.session:
                        request.session[key] = value
                url = next_url
            else:
                url += '?' + urlencode({'error': 'OIDC authent callback, no user error'})
        except Exception as e:
            warning(repr(e))
            url += '?' + urlencode({'error': str(e)})
        return url

    def logout_callback(self, request, next_url: str, failure_url: str) -> str:
        url = failure_url
        try:
            state = request.GET['state']
            session_state = request.session.get(constants.SESSION_LOGOUT_STATE)
            if state == session_state:
                if request.user.is_authenticated:
                    auth.logout(request)
                self._clear_cache(request)
                url = next_url
            else:
                request.session.pop(constants.SESSION_LOGOUT_STATE, None)
                request.session.save()
                url += '?' + urlencode({'error': 'OIDC logout callback, bad state error'})
        except Exception as e:
            msg = e.args[0]
            warning(msg)
            url += '?' + urlencode({'error': str(msg)})
        return url


class LogoutView(CacheBaseView):
    """
    Logout user from the application, called by RP user-agent.
    """
    http_method_names = ['get']

    def get(self, request):
        next_url = request.GET.get(settings.OIDC_REDIRECT_OK_FIELD_NAME)
        failure_url = request.GET.get(settings.OIDC_REDIRECT_ERROR_FIELD_NAME)
        if not next_url:
            return HttpResponseBadRequest(f"{settings.OIDC_REDIRECT_OK_FIELD_NAME} parameter is required".encode('utf8'))
        if not failure_url:
            return HttpResponseBadRequest(f"{settings.OIDC_REDIRECT_ERROR_FIELD_NAME} parameter is required".encode('utf8'))
        try:
            if constants.SESSION_ID_TOKEN not in request.session:
                raise ValueError("id_token is missing from the session, cannot logout")
            id_token = request.session[constants.SESSION_ID_TOKEN]
            return self.logout(request, id_token, next_url, failure_url)
        except Exception as e:
            return HttpResponseRedirect(f"{failure_url}?{urlencode({'error': e.args[0]})}")

    def logout(self, request, id_token, next_url, failure_url):
        BlacklistedToken.blacklist(id_token)
        self._clear_cache(request)
        if request.user.is_authenticated:
            auth.logout(request)
        return HttpResponseRedirect(next_url)


class TotalLogoutView(LogoutView):
    """
    Logout user from the application, the OP and any application connected to the OP , called by RP user-agent.
    """
    def logout(self, request, id_token, next_url, failure_url):
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
            redirect_url = f'{end_session_url}?{urlencode(logout_params)}'
            return HttpResponseRedirect(redirect_url)
        else:
            return super().logout(request, id_token, next_url, failure_url)


class LogoutByOPView(CacheBaseView):
    """
    Logout user, called by OP.
    """
    http_method_names = ['get']

    def get(self, request):
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
            msg = e.args[0]
            warning(msg)
            return HttpResponseBadRequest(msg.encode('utf8'))
