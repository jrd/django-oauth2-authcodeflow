from re import escape
from unittest.mock import (
    MagicMock,
    patch,
)

import pytest
from django.contrib.sessions.backends.base import SessionBase
from django.contrib.sessions.middleware import SessionMiddleware
from django.core.exceptions import SuspiciousOperation
from django.http import (
    HttpResponse,
    HttpResponseRedirect,
)
from jose.exceptions import JWTError

from oauth2_authcodeflow import constants
from oauth2_authcodeflow.views import (
    AuthenticateView,
    BadRequestException,
    CacheBaseView,
    CallbackView,
    LogoutByOPView,
    LogoutView,
    TotalLogoutView,
    UrlParamsMixin,
)


@pytest.fixture
def sf():
    """
    Session factory
    takes a request as argument and create a session (not saved) on it
    """
    def session_factory(request):
        middleware = SessionMiddleware(lambda x: None)
        middleware.process_request(request)
        return request.session
    yield session_factory


class TestCacheBaseView:
    @patch('oauth2_authcodeflow.views.CacheBaseView._set_cache')
    @patch('oauth2_authcodeflow.views.View.dispatch')
    def test_dispatch(self, dispatch, set_cache, rf):
        exp_resp = HttpResponse()
        dispatch.return_value = exp_resp
        view = CacheBaseView()
        request = rf.get('/')
        resp = view.dispatch(request, 'arg1', 'arg2', arg3='42')
        assert resp is exp_resp
        assert resp['Pragma'] == 'no-cache'
        assert resp['Expires'] == '0'
        set_cache.assert_called_once_with(request)
        dispatch.assert_called_once_with(request, 'arg1', 'arg2', arg3='42')

    @patch('oauth2_authcodeflow.views.CacheBaseView.get_oidc_urls')
    def test_set_cache(self, get_oidc_urls, rf, sf):
        get_oidc_urls.return_value = dict(key1='value1', key2=42)
        request = rf.get('/')
        session = sf(request)
        view = CacheBaseView()
        view._set_cache(request)
        assert session['key1'] == 'value1'
        assert session['key2'] == 42
        get_oidc_urls.assert_called_once_with(session)

    def test_clear_cache(self, db, rf, sf):
        request = rf.get('/')
        session = sf(request)
        session['oidc_id_token'] = 'abc123'
        session['oidc_state'] = 'state'
        session['oidc_nonce'] = 'nonce'
        session['oidc_callback'] = 'some/url'
        view = CacheBaseView()
        view._clear_cache(request)
        assert 'oidc_id_token' not in session
        assert 'oidc_state' not in session
        assert 'oidc_nonce' not in session
        assert 'oidc_callback' in session
        assert session.session_key is not None


class TestUrlParamsMixin:
    def test_get_url_with_params(self):
        mixin = UrlParamsMixin()
        assert mixin.get_url_with_params('/toto/tutu') == '/toto/tutu'
        assert mixin.get_url_with_params('/toto/tutu', truc='machin') == '/toto/tutu?truc=machin'
        assert mixin.get_url_with_params(
            '/toto/tutu',
            remember='1',
            url='https://some.example.com/where',
        ) == '/toto/tutu?remember=1&url=https%3A%2F%2Fsome.example.com%2Fwhere'


class TestAuthenticateView:
    def test_get_from_cli(self, rf):
        view = AuthenticateView()
        assert view.get_from_cli(rf.get('/')) is False
        assert view.get_from_cli(rf.get('/', {constants.OIDC_FROM_CLI_QUERY_STRING: '1'})) is True

    def test_get_next_and_failure_url(self, db, rf, sf, settings):
        view = AuthenticateView()
        request = rf.get('/some/url', dict(ok='', fail=''))
        session = sf(request)
        settings.OIDC_REDIRECT_OK_FIELD_NAME = 'ok'
        settings.OIDC_REDIRECT_ERROR_FIELD_NAME = 'fail'
        with pytest.raises(SuspiciousOperation, match=escape("ok parameter is required")):
            view.get_next_and_failure_url(request, False)
        request = rf.get('/some/url', dict(ok='/profile', fail=''))
        session = sf(request)
        settings.OIDC_REDIRECT_OK_FIELD_NAME = 'ok'
        settings.OIDC_REDIRECT_ERROR_FIELD_NAME = 'fail'
        with pytest.raises(SuspiciousOperation, match=escape("fail parameter is required")):
            view.get_next_and_failure_url(request, False)
        request = rf.get('/some/url', dict(ok='/profile', fail='/error'))
        session = sf(request)
        settings.OIDC_REDIRECT_OK_FIELD_NAME = 'ok'
        settings.OIDC_REDIRECT_ERROR_FIELD_NAME = 'fail'
        assert view.get_next_and_failure_url(request, False) == ('/profile', '/error')
        assert session.session_key is None
        request = rf.get('/some/url')
        session = sf(request)
        settings.OIDC_REDIRECT_OK_FIELD_NAME = 'ok'
        settings.OIDC_REDIRECT_ERROR_FIELD_NAME = 'fail'
        assert view.get_next_and_failure_url(request, False) == ('/', '/')
        assert session.session_key is None
        request = rf.get('/some/url', dict(ok='/profile', fail='/error'))
        session = sf(request)
        settings.OIDC_REDIRECT_OK_FIELD_NAME = 'ok'
        settings.OIDC_REDIRECT_ERROR_FIELD_NAME = 'fail'
        assert view.get_next_and_failure_url(request, True) == ('/FROM_CLI_OK', '/FROM_CLI_FAIL')
        assert session.session_key is not None
        request = rf.get('/some/url')
        session = sf(request)
        assert view.get_next_and_failure_url(request, True) == ('/FROM_CLI_OK', '/FROM_CLI_FAIL')
        assert session.session_key is not None

    def test_get_claims_parameter(self, rf, sf, settings):
        view = AuthenticateView()
        request = rf.get('/some/url')
        session = sf(request)
        settings.OIDC_RP_USERINFO_CLAIMS = {}
        settings.OIDC_RP_TOKEN_CLAIMS = {}
        assert view.get_claims_parameter(request) is None
        session[constants.SESSION_OP_CLAIMS_PARAMETER_SUPPORTED] = False
        assert view.get_claims_parameter(request) is None
        session[constants.SESSION_OP_CLAIMS_PARAMETER_SUPPORTED] = True
        assert view.get_claims_parameter(request) is None
        settings.OIDC_RP_USERINFO_CLAIMS = {'is_admin': None}
        assert view.get_claims_parameter(request) == {'userinfo': {'is_admin': None}}
        settings.OIDC_RP_TOKEN_CLAIMS = {'group': None}
        assert view.get_claims_parameter(request) == {'userinfo': {'is_admin': None}, 'id_token': {'group': None}}

    @patch('oauth2_authcodeflow.views.get_random_string')
    def test_fill_params_for_pkce(self, get_random_string, rf):
        view = AuthenticateView()
        get_random_string.return_value = 'a' * 50 + 'b' * 50
        session_updates = {}
        auth_params = {}
        view.fill_params_for_pkce(rf.get('/'), session_updates, auth_params, False)
        assert session_updates == {constants.SESSION_CHALLENGE: 'a' * 50 + 'b' * 50}
        assert auth_params == {'code_challenge_method': 'S256', 'code_challenge': 'PdulAGejIt-jJUoVpXRJw53-Sp0c3F5uO2Z4sVUXYUg'}
        get_random_string.return_value = 'a' * 50 + 'b' * 49 + 'c'
        view.fill_params_for_pkce(rf.get('/'), session_updates, auth_params, True)
        assert session_updates == {constants.SESSION_CHALLENGE: 'a' * 50 + 'b' * 49 + 'c'}
        assert auth_params == {'code_challenge_method': 'S256', 'code_challenge': 'QQsQOhuFwz1ltjELmBkzeRGE88KAuVDfPPrSxUnSjn4'}

    @patch('oauth2_authcodeflow.views.jwt')
    @patch('oauth2_authcodeflow.views.get_random_string')
    def test_fill_params_without_pkce(self, get_random_string, jwt, rf, settings):
        view = AuthenticateView()
        settings.OIDC_RANDOM_SIZE = 5
        settings.SECRET_KEY = 'django_key'
        jwt.encode.return_value = 'bepo'
        get_random_string.side_effect = ['abcde', '12345']
        session_updates = {}
        auth_params = {}
        view.fill_params_without_pkce(rf.get('/'), session_updates, auth_params, False)
        assert session_updates == {constants.SESSION_STATE: 'abcde', constants.SESSION_NONCE: '12345'}
        assert auth_params == {'state': 'abcde', 'nonce': '12345'}
        jwt.encode.assert_not_called()
        request = rf.get('/')
        request.session = MagicMock(session_key='auie')
        jwt.encode.return_value = 'bepo'
        get_random_string.side_effect = ['abcde', '12345']
        session_updates = {}
        auth_params = {}
        view.fill_params_without_pkce(request, session_updates, auth_params, True)
        assert session_updates == {constants.SESSION_STATE: 'bepo', constants.SESSION_NONCE: 'abcde'}
        assert auth_params == {'state': 'bepo', 'nonce': 'abcde'}
        jwt.encode.assert_called_once_with({'session_key': 'auie'}, 'django_key', algorithm='HS256')

    @patch('oauth2_authcodeflow.views.AuthenticateView.fill_params_without_pkce')
    @patch('oauth2_authcodeflow.views.AuthenticateView.fill_params_for_pkce')
    @patch('oauth2_authcodeflow.views.AuthenticateView.get_claims_parameter')
    def test_get_auth_params(self, get_claims_parameter, fill_params_for_pkce, fill_params_without_pkce, rf, settings):
        view = AuthenticateView()
        settings.OIDC_RP_CLIENT_ID = 'test client_id'
        settings.OIDC_RP_FORCE_CONSENT_PROMPT = True
        get_claims_parameter.return_value = None

        def fill_params(session_updates, auth_params, new_session_updates, new_auth_params):
            session_updates.update(new_session_updates)
            auth_params.update(new_auth_params)

        pkce_new_session_updates = {constants.SESSION_CHALLENGE: 'challenge'}
        pkce_new_auth_params = {'code_challenge_method': 'S256', 'code_challenge': 'code challenge'}
        not_pkce_new_session_updates = {constants.SESSION_STATE: 'test state', constants.SESSION_NONCE: 'test nonce'}
        not_pkce_new_auth_params = {'state': 'test state', 'nonce': 'test nonce'}
        fill_params_for_pkce.side_effect = lambda r, s, a, f: fill_params(s, a, pkce_new_session_updates, pkce_new_auth_params)
        fill_params_without_pkce.side_effect = lambda r, s, a, f: fill_params(s, a, not_pkce_new_session_updates, not_pkce_new_auth_params)
        request = rf.get('/')
        assert view.get_auth_params(request, False, False, ['openid', 'email']) == (
            {constants.SESSION_STATE: 'test state', constants.SESSION_NONCE: 'test nonce'},
            {
                'response_type': 'code',
                'client_id': 'test client_id',
                'scope': 'openid email',
                'redirect_uri': 'http://testserver/oidc/callback',
                'prompt': 'consent',
                'state': 'test state',
                'nonce': 'test nonce',
            },
        )
        get_claims_parameter.assert_called_once_with(request)
        get_claims_parameter.reset_mock()
        fill_params_for_pkce.assert_not_called()
        fill_params_for_pkce.reset_mock()
        fill_params_without_pkce.assert_called_once()
        fill_params_without_pkce.reset_mock()
        settings.OIDC_RP_FORCE_CONSENT_PROMPT = False
        assert view.get_auth_params(request, True, False, ['openid', 'email', 'offline_access']) == (
            {constants.SESSION_STATE: 'test state', constants.SESSION_NONCE: 'test nonce'},
            {
                'response_type': 'code',
                'client_id': 'test client_id',
                'scope': 'openid email offline_access',
                'redirect_uri': 'http://testserver/oidc/callback',
                'prompt': 'consent',
                'state': 'test state',
                'nonce': 'test nonce',
            },
        )
        get_claims_parameter.assert_called_once_with(request)
        get_claims_parameter.reset_mock()
        fill_params_for_pkce.assert_not_called()
        fill_params_for_pkce.reset_mock()
        fill_params_without_pkce.assert_called_once()
        fill_params_without_pkce.reset_mock()
        assert view.get_auth_params(request, False, True, ['openid', 'email']) == (
            {constants.SESSION_CHALLENGE: 'challenge'},
            {
                'response_type': 'code',
                'client_id': 'test client_id',
                'scope': 'openid email',
                'redirect_uri': 'http://testserver/oidc/callback',
                'code_challenge_method': 'S256',
                'code_challenge': 'code challenge',
            },
        )
        get_claims_parameter.assert_called_once_with(request)
        get_claims_parameter.reset_mock()
        fill_params_for_pkce.assert_called_once()
        fill_params_for_pkce.reset_mock()
        fill_params_without_pkce.assert_not_called()
        fill_params_without_pkce.reset_mock()
        get_claims_parameter.return_value = dict(userinfo={'is_admin': None}, id_token={'group': None})
        assert view.get_auth_params(request, True, True, ['openid', 'email']) == (
            {constants.SESSION_CHALLENGE: 'challenge'},
            {
                'response_type': 'code',
                'client_id': 'test client_id',
                'scope': 'openid email',
                'redirect_uri': 'http://testserver/oidc/callback',
                'claims': '{"userinfo": {"is_admin": null}, "id_token": {"group": null}}',
                'code_challenge_method': 'S256',
                'code_challenge': 'code challenge',
            },
        )
        get_claims_parameter.assert_called_once_with(request)
        get_claims_parameter.reset_mock()
        fill_params_for_pkce.assert_called_once()
        fill_params_for_pkce.reset_mock()
        fill_params_without_pkce.assert_not_called()
        fill_params_without_pkce.reset_mock()

    @patch('oauth2_authcodeflow.views.AuthenticateView.get_url_with_params')
    @patch('oauth2_authcodeflow.views.AuthenticateView.get_auth_params')
    @patch('oauth2_authcodeflow.views.AuthenticateView.get_next_and_failure_url')
    @patch('oauth2_authcodeflow.views.AuthenticateView.get_from_cli')
    def test_get(self, get_from_cli, get_next_and_failure_url, get_auth_params, get_url_with_params, db, rf, sf, settings):
        view = AuthenticateView()
        settings.OIDC_RP_SCOPES = ['openid', 'email', 'offline_access']
        settings.OIDC_RP_USE_PKCE = True
        get_from_cli.return_value = False
        get_next_and_failure_url.return_value = '/ok', '/ko'
        get_auth_params.return_value = (
            {constants.SESSION_CHALLENGE: 'challenge'},
            {
                'response_type': 'code',
                'client_id': 'test client_id',
                'scope': 'openid email offline_access',
                'redirect_uri': 'http://testserver/oidc/callback',
                'code_challenge_method': 'S256',
                'code_challenge': 'code challenge',
            },
        )
        get_url_with_params.return_value = '/login'
        request = rf.get('/')
        session = sf(request)
        session[constants.SESSION_OP_AUTHORIZATION_URL] = '/authent'
        response = view.get(request)
        assert response.status_code == 302
        assert response.headers['Location'] == '/login'
        assert session.session_key is not None
        assert session[constants.SESSION_NEXT_URL] == '/ok'
        assert session[constants.SESSION_FAIL_URL] == '/ko'
        assert session[constants.SESSION_CHALLENGE] == 'challenge'
        get_from_cli.assert_called_once_with(request)
        get_from_cli.reset_mock()
        get_next_and_failure_url.assert_called_once_with(request, False)
        get_next_and_failure_url.reset_mock()
        get_auth_params.assert_called_once_with(request, False, True, ['openid', 'email', 'offline_access'])
        get_auth_params.reset_mock()
        get_url_with_params.assert_called_once_with(
            '/authent',
            response_type='code',
            client_id='test client_id',
            scope='openid email offline_access',
            redirect_uri='http://testserver/oidc/callback',
            code_challenge_method='S256',
            code_challenge='code challenge',
        )
        get_url_with_params.reset_mock()
        get_from_cli.return_value = True
        get_auth_params.return_value = (
            {constants.SESSION_CHALLENGE: 'challenge'},
            {
                'response_type': 'code',
                'client_id': 'test client_id',
                'scope': 'openid email',
                'redirect_uri': 'http://testserver/oidc/callback',
                'code_challenge_method': 'S256',
                'code_challenge': 'code challenge',
            },
        )
        request = rf.get('/')
        session = sf(request)
        session[constants.SESSION_OP_AUTHORIZATION_URL] = '/authent'
        response = view.get(request)
        assert response.content == b"Go to:\n/login\n"
        assert response.status_code == 200
        assert session.session_key is not None
        assert session[constants.SESSION_NEXT_URL] == '/ok'
        assert session[constants.SESSION_FAIL_URL] == '/ko'
        assert session[constants.SESSION_CHALLENGE] == 'challenge'
        get_from_cli.assert_called_once_with(request)
        get_next_and_failure_url.assert_called_once_with(request, True)
        get_auth_params.assert_called_once_with(request, True, False, ['openid', 'email'])
        get_url_with_params.assert_called_once_with(
            '/authent',
            response_type='code',
            client_id='test client_id',
            scope='openid email',
            redirect_uri='http://testserver/oidc/callback',
            code_challenge_method='S256',
            code_challenge='code challenge',
        )


class TestCallbackView:
    def test_init(self):
        view = CallbackView()
        assert view.SessionStore
        assert issubclass(view.SessionStore, SessionBase)

    @patch('oauth2_authcodeflow.views.jwt')
    def test_get_from_cli(self, jwt, rf):
        view = CallbackView()
        jwt.get_unverified_header.side_effect = JWTError
        request = rf.get('/')
        assert view.get_from_cli(request) is False
        request = rf.get('/', {'state': 'some.state.sign'})
        assert view.get_from_cli(request) is False
        jwt.get_unverified_header.assert_called_once_with('some.state.sign')
        jwt.get_unverified_header.reset_mock()
        jwt.get_unverified_header.side_effect = None
        request = rf.get('/', {'state': 'some.state.sign'})
        assert view.get_from_cli(request) is True
        jwt.get_unverified_header.assert_called_once_with('some.state.sign')

    @patch('oauth2_authcodeflow.views.jwt')
    def test_prepare_session_and_get_state(self, jwt, db, rf, sf, settings):
        view = CallbackView()
        jwt.decode.side_effect = JWTError
        settings.SECRET_KEY = 'django_key'
        request = rf.get('/')
        assert view.prepare_session_and_get_state(request, False) is None
        request = rf.get('/', {'state': 'some.state.sign'})
        assert view.prepare_session_and_get_state(request, False) == 'some.state.sign'
        with pytest.raises(BadRequestException, match=escape("state appears to be a JWT but the signature failed")):
            view.prepare_session_and_get_state(request, True)
        jwt.decode.side_effect = None
        jwt.decode.return_value = {}
        with pytest.raises(BadRequestException, match=escape("state appears to be a JWT but the signature failed")):
            view.prepare_session_and_get_state(request, True)
        stored_session = sf(rf.get('/'))
        stored_session['KEY1'] = 'value1'
        stored_session['KEY2'] = 'value2'
        stored_session.save()
        request = rf.get('/', {'state': 'some.state.sign'})
        session = sf(request)
        session['SOME_KEY'] = 'some value'
        session['KEY2'] = 'value3'
        jwt.decode.return_value = {'session_key': stored_session.session_key}
        assert view.prepare_session_and_get_state(request, True) == 'some.state.sign'
        assert request.session.get('SOME_KEY', '') == 'some value'
        assert request.session.get('KEY1', '') == 'value1'
        assert request.session.get('KEY2', '') == 'value2'

    def test_get_next_and_failure_url(self, rf, sf):
        view = CallbackView()
        request = rf.get('/')
        session = sf(request)
        with pytest.raises(
            BadRequestException,
            match=escape(f"{constants.SESSION_NEXT_URL} and {constants.SESSION_FAIL_URL} session parameters should be filled"),
        ):
            view.get_next_and_failure_url(request, True)
        session[constants.SESSION_NEXT_URL] = '/next'
        session[constants.SESSION_FAIL_URL] = '/fail'
        assert view.get_next_and_failure_url(request, True) == ('/next', '/fail')
        assert view.get_next_and_failure_url(request, False) == ('/next', '/fail')

    @patch('oauth2_authcodeflow.views.CallbackView.logout_callback')
    @patch('oauth2_authcodeflow.views.CallbackView.auth_callback')
    @patch('oauth2_authcodeflow.views.CallbackView._clear_cache')
    @patch('oauth2_authcodeflow.views.auth')
    def test_get_redirect_url(self, auth, clear_cache, auth_callback, logout_callback, rf, sf, settings):
        view = CallbackView()
        # error case
        settings.OIDC_RP_USE_PKCE = True
        auth_callback.return_value = '/auth/url'
        logout_callback.return_value = '/logout/url'
        request = rf.get('/', {'error': 'some error'})
        request.user = MagicMock(is_authenticated=False)
        session = sf(request)
        assert view.get_redirect_url(request, False, False, 'test state', '/next', '/fail') == "/fail?error=some+error"
        auth.logout.assert_not_called()
        clear_cache.assert_called_once_with(request)
        clear_cache.reset_mock()
        auth_callback.assert_not_called()
        logout_callback.assert_not_called()
        request.user = MagicMock(is_authenticated=True)
        assert view.get_redirect_url(request, False, False, 'test state', '/next', '/fail') == "/fail?error=some+error"
        auth.logout.assert_called_once_with(request)
        auth.logout.reset_mock()
        clear_cache.assert_called_once_with(request)
        clear_cache.reset_mock()
        auth_callback.assert_not_called()
        logout_callback.assert_not_called()
        # auth callback case
        request = rf.get('/', {'code': 'some code'})
        request.user = MagicMock(is_authenticated=True)
        session = sf(request)
        assert view.get_redirect_url(request, False, False, 'test state', '/next', '/fail') == "/auth/url"
        auth.logout.assert_not_called()
        clear_cache.assert_not_called()
        auth_callback.assert_called_once_with(request, '/next', '/fail', False)
        auth_callback.reset_mock()
        logout_callback.assert_not_called()
        assert view.get_redirect_url(request, True, False, 'test state', '/next', '/fail') == "/auth/url"
        auth.logout.assert_not_called()
        clear_cache.assert_not_called()
        auth_callback.assert_called_once_with(request, '/next', '/fail', True)
        auth_callback.reset_mock()
        logout_callback.assert_not_called()
        settings.OIDC_RP_USE_PKCE = False
        assert view.get_redirect_url(request, False, False, 'test state', '/next', '/fail') == "/auth/url"
        auth.logout.assert_not_called()
        clear_cache.assert_not_called()
        auth_callback.assert_called_once_with(request, '/next', '/fail', False)
        auth_callback.reset_mock()
        logout_callback.assert_not_called()
        assert view.get_redirect_url(request, True, False, 'test state', '/next', '/fail') == "/auth/url"
        auth.logout.assert_not_called()
        clear_cache.assert_not_called()
        auth_callback.assert_called_once_with(request, '/next', '/fail', True)
        auth_callback.reset_mock()
        logout_callback.assert_not_called()
        # unknown case
        request = rf.get('/')
        request.user = MagicMock(is_authenticated=True)
        session = sf(request)
        assert view.get_redirect_url(request, False, False, None, '/next', '/fail') == "/fail?error=Unknown+OIDC+callback"
        auth.logout.assert_not_called()
        logout_callback.assert_not_called()
        auth_callback.assert_not_called()
        session[constants.SESSION_LOGOUT_STATE] = 'logout state'
        assert view.get_redirect_url(request, False, False, None, '/next', '/fail') == "/fail?error=Unknown+OIDC+callback"
        auth.logout.assert_not_called()
        logout_callback.assert_not_called()
        auth_callback.assert_not_called()
        # logout callback case
        assert view.get_redirect_url(request, False, False, 'test state', '/next', '/fail') == "/logout/url"
        auth.logout.assert_not_called()
        clear_cache.assert_not_called()
        auth_callback.assert_not_called()
        logout_callback.assert_called_once_with(request, '/next', '/fail')

    def test_build_response_from_cli(self, rf, sf, settings):
        view = CallbackView()
        settings.OIDC_AUTHORIZATION_HEADER_PREFIX = 'Prefix'
        request = rf.get('/')
        session = sf(request)
        session[constants.SESSION_ID_TOKEN] = 'some.id.token'
        with pytest.raises(BadRequestException, match="^Error: $"):
            view.build_response_from_cli(request, '/some/url')
        with pytest.raises(BadRequestException, match="^Error: some message$"):
            view.build_response_from_cli(request, '/some/url?error=some+message')
        response = view.build_response_from_cli(request, '/FROM_CLI_OK')
        assert response.status_code == 200
        assert response.headers['Content-Type'] == 'text/plain'
        assert response.content == b"Header:\n  Authorization: Prefix some.id.token\n"

    def test_build_response_from_http(self, rf):
        view = CallbackView()
        response = view.build_response_from_http(rf.get('/'), '/some/url')
        assert response.status_code == 302
        assert response.headers['Location'] == '/some/url'

    @patch('oauth2_authcodeflow.views.CallbackView.build_response_from_http')
    @patch('oauth2_authcodeflow.views.CallbackView.build_response_from_cli')
    def test_build_response(self, build_response_from_cli, build_response_from_http, db, rf, sf):
        request = rf.get('/')
        build_response_from_cli.side_effect = lambda request, url: url + '/cli'
        build_response_from_http.side_effect = lambda request, url: url + '/http'
        session = sf(request)
        assert session.session_key is None
        view = CallbackView()
        assert view.build_response(request, True, '/any/url') == '/any/url/cli'
        assert session.session_key is not None
        build_response_from_cli.assert_called_once_with(request, '/any/url')
        build_response_from_cli.reset_mock()
        build_response_from_http.assert_not_called()
        session = sf(request)
        assert session.session_key is None
        assert view.build_response(request, False, '/any/url') == '/any/url/http'
        assert session.session_key is not None
        build_response_from_cli.assert_not_called()
        build_response_from_http.assert_called_once_with(request, '/any/url')

    @patch('oauth2_authcodeflow.views.CallbackView.build_response')
    @patch('oauth2_authcodeflow.views.CallbackView.get_redirect_url')
    @patch('oauth2_authcodeflow.views.CallbackView.get_next_and_failure_url')
    @patch('oauth2_authcodeflow.views.CallbackView.prepare_session_and_get_state')
    @patch('oauth2_authcodeflow.views.CallbackView.get_from_cli')
    def test_get(self, get_from_cli, prepare_session_and_get_state, get_next_and_failure_url, get_redirect_url, build_response, rf, sf, settings):
        view = CallbackView()
        settings.OIDC_RP_USE_PKCE = True
        get_from_cli.return_value = False
        prepare_session_and_get_state.side_effect = BadRequestException("some prepare error")
        get_next_and_failure_url.side_effect = BadRequestException("some urls error")
        get_redirect_url.return_value = '/redirect/url'
        build_response.side_effect = lambda request, from_cli, url: HttpResponse(url) if from_cli else HttpResponseRedirect(url)
        request = rf.get('/')
        sf(request)
        response = view.get(request)
        assert response.status_code == 400
        assert response.content == b"some prepare error"
        get_from_cli.assert_called_once_with(request)
        get_from_cli.reset_mock()
        prepare_session_and_get_state.assert_called_once_with(request, False)
        prepare_session_and_get_state.reset_mock()
        prepare_session_and_get_state.side_effect = None
        prepare_session_and_get_state.return_value = 'some state'
        get_next_and_failure_url.assert_not_called()
        get_redirect_url.assert_not_called()
        build_response.assert_not_called()
        response = view.get(request)
        assert response.status_code == 400
        assert response.content == b"some urls error"
        get_from_cli.assert_called_once_with(request)
        get_from_cli.reset_mock()
        prepare_session_and_get_state.assert_called_once_with(request, False)
        prepare_session_and_get_state.reset_mock()
        get_next_and_failure_url.assert_called_once_with(request, False)
        get_next_and_failure_url.reset_mock()
        get_next_and_failure_url.side_effect = None
        get_next_and_failure_url.return_value = ('/next', '/fail')
        get_redirect_url.assert_not_called()
        build_response.assert_not_called()
        response = view.get(request)
        assert response.status_code == 302
        assert 'Location' in response.headers
        get_from_cli.assert_called_once_with(request)
        get_from_cli.reset_mock()
        get_from_cli.return_value = True
        prepare_session_and_get_state.assert_called_once_with(request, False)
        prepare_session_and_get_state.reset_mock()
        get_next_and_failure_url.assert_called_once_with(request, False)
        get_next_and_failure_url.reset_mock()
        get_redirect_url.assert_called_once_with(request, True, False, 'some state', '/next', '/fail')
        get_redirect_url.reset_mock()
        build_response.assert_called_once_with(request, False, '/redirect/url')
        build_response.reset_mock()
        response = view.get(request)
        assert response.status_code == 200
        assert 'Location' not in response.headers
        assert b'/redirect/url' in response.content
        get_from_cli.assert_called_once_with(request)
        prepare_session_and_get_state.assert_called_once_with(request, True)
        get_next_and_failure_url.assert_called_once_with(request, True)
        get_redirect_url.assert_called_once_with(request, False, True, 'some state', '/next', '/fail')
        build_response.assert_called_once_with(request, True, '/redirect/url')

    def test_extract_auth_callback_params_with_pkce(self, rf, sf):
        view = CallbackView()
        request = rf.get('/')
        sf(request)
        with pytest.raises(SuspiciousOperation, match=escape("challenge not found in session")):
            view.extract_auth_callback_params_with_pkce(request)
        request.session[constants.SESSION_CHALLENGE] = ''
        with pytest.raises(SuspiciousOperation, match=escape("challenge not found in session")):
            view.extract_auth_callback_params_with_pkce(request)
        request.session[constants.SESSION_CHALLENGE] = 'challenge'
        assert view.extract_auth_callback_params_with_pkce(request) == (None, None, 'challenge')
        assert constants.SESSION_CHALLENGE not in request.session

    def test_extract_auth_callback_params_without_pkce(self, rf, sf):
        view = CallbackView()
        request = rf.get('/')
        sf(request)
        with pytest.raises(SuspiciousOperation, match=escape("state not found in session")):
            view.extract_auth_callback_params_without_pkce(request)
        request.session[constants.SESSION_STATE] = 'some state'
        with pytest.raises(SuspiciousOperation, match=escape("state values do not match")):
            view.extract_auth_callback_params_without_pkce(request)
        request = rf.get('/', {'state': 'some state'})
        sf(request)
        request.session[constants.SESSION_STATE] = 'some state'
        with pytest.raises(SuspiciousOperation, match=escape("nonce not found in session")):
            view.extract_auth_callback_params_without_pkce(request)
        request.session[constants.SESSION_STATE] = 'some state'
        request.session[constants.SESSION_NONCE] = 'some nonce'
        assert view.extract_auth_callback_params_without_pkce(request) == ('some state', 'some nonce', None)
        assert constants.SESSION_STATE not in request.session
        assert constants.SESSION_NONCE not in request.session

    @patch('oauth2_authcodeflow.views.CallbackView.extract_auth_callback_params_without_pkce')
    @patch('oauth2_authcodeflow.views.CallbackView.extract_auth_callback_params_with_pkce')
    def test_extract_auth_callback_params(self, extract_auth_callback_params_with_pkce, extract_auth_callback_params_without_pkce, rf):
        view = CallbackView()
        request = rf.get('/')
        extract_auth_callback_params_with_pkce.return_value = (None, None, 'some challenge')
        extract_auth_callback_params_without_pkce.return_value = ('some state', 'some nonce', None)
        assert view.extract_auth_callback_params(request, True) == (None, None, 'some challenge')
        extract_auth_callback_params_with_pkce.assert_called_once_with(request)
        extract_auth_callback_params_with_pkce.reset_mock()
        extract_auth_callback_params_without_pkce.assert_not_called()
        assert view.extract_auth_callback_params(request, False) == ('some state', 'some nonce', None)
        extract_auth_callback_params_with_pkce.assert_not_called()
        extract_auth_callback_params_without_pkce.assert_called_once_with(request)

    @patch('oauth2_authcodeflow.views.CallbackView.extract_auth_callback_params')
    @patch('oauth2_authcodeflow.views.auth')
    def test_auth_callback(self, auth, extract_auth_callback_params, db, rf, sf):
        view = CallbackView()
        auth.authenticate.return_value = None
        auth.login.side_effect = lambda request, user: sf(request).save()
        extract_auth_callback_params.side_effect = BadRequestException("some error")
        request = rf.get('/', {'code': 'some code'})
        session = sf(request)
        session['SOME_KEY'] = 'a value'
        session.save()
        session_key = session.session_key
        assert view.auth_callback(request, '/next', '/fail', True) == '/fail?error=some+error'
        assert request.session.session_key == session_key
        assert request.session.get('SOME_KEY', '') == 'a value'
        extract_auth_callback_params.assert_called_once_with(request, True)
        extract_auth_callback_params.reset_mock()
        extract_auth_callback_params.side_effect = None
        extract_auth_callback_params.return_value = ('some state', 'some nonce', None)
        auth.authenticate.assert_not_called()
        auth.login.assert_not_called()
        assert view.auth_callback(request, '/next', '/fail', False) == '/fail?error=OIDC+authent+callback%2C+no+user+error'
        assert request.session.session_key == session_key
        assert request.session.get('SOME_KEY', '') == 'a value'
        extract_auth_callback_params.assert_called_once_with(request, False)
        extract_auth_callback_params.reset_mock()
        extract_auth_callback_params.return_value = (None, None, 'some challenge')
        auth.authenticate.assert_called_once_with(request, use_pkce=False, code='some code', state='some state', nonce='some nonce', code_verifier=None)
        auth.authenticate.reset_mock()
        auth.authenticate.return_value = MagicMock(is_active=False)
        auth.login.assert_not_called()
        assert view.auth_callback(request, '/next', '/fail', True) == '/fail?error=OIDC+authent+callback%2C+no+user+error'
        assert request.session.session_key == session_key
        assert request.session.get('SOME_KEY', '') == 'a value'
        extract_auth_callback_params.assert_called_once_with(request, True)
        extract_auth_callback_params.reset_mock()
        auth.authenticate.assert_called_once_with(request, use_pkce=True, code='some code', state=None, nonce=None, code_verifier='some challenge')
        auth.authenticate.reset_mock()
        auth.authenticate.return_value = MagicMock(is_active=True)
        auth.login.assert_not_called()
        assert view.auth_callback(request, '/next', '/fail', True) == '/next'
        assert request.session.session_key != session_key
        assert request.session.get('SOME_KEY', '') == 'a value'
        extract_auth_callback_params.assert_called_once_with(request, True)
        auth.authenticate.assert_called_once_with(request, use_pkce=True, code='some code', state=None, nonce=None, code_verifier='some challenge')
        auth.login.assert_called_once_with(request, auth.authenticate.return_value)

    @patch('oauth2_authcodeflow.views.CallbackView._clear_cache')
    @patch('oauth2_authcodeflow.views.auth')
    def test_logout_callback(self, auth, clear_cache, db, rf, sf):
        view = CallbackView()
        clear_cache.side_effect = lambda request: (request.session.pop(constants.SESSION_LOGOUT_STATE, None), request.session.save())
        request = rf.get('/')
        request.user = MagicMock(is_authenticated=True)
        session = sf(request)
        assert view.logout_callback(request, '/next', '/fail') == '/fail?error=%27state%27'
        assert request.session.session_key is None
        auth.logout.assert_not_called()
        clear_cache.assert_not_called()
        request = rf.get('/', {'state': 'some state'})
        request.user = MagicMock(is_authenticated=True)
        session = sf(request)
        assert view.logout_callback(request, '/next', '/fail') == '/fail?error=OIDC+logout+callback%2C+bad+state+error'
        assert request.session.session_key is not None
        assert constants.SESSION_LOGOUT_STATE not in request.session
        auth.logout.assert_not_called()
        clear_cache.assert_not_called()
        request = rf.get('/', {'state': 'some state'})
        request.user = MagicMock(is_authenticated=True)
        session = sf(request)
        session[constants.SESSION_LOGOUT_STATE] = 'logout state'
        assert view.logout_callback(request, '/next', '/fail') == '/fail?error=OIDC+logout+callback%2C+bad+state+error'
        assert request.session.session_key is not None
        assert constants.SESSION_LOGOUT_STATE not in request.session
        auth.logout.assert_not_called()
        clear_cache.assert_not_called()
        request = rf.get('/', {'state': 'logout state'})
        request.user = MagicMock(is_authenticated=True)
        session = sf(request)
        session[constants.SESSION_LOGOUT_STATE] = 'logout state'
        assert view.logout_callback(request, '/next', '/fail') == '/next'
        assert request.session.session_key is not None
        assert constants.SESSION_LOGOUT_STATE not in request.session
        auth.logout.assert_called_once_with(request)
        auth.logout.reset_mock()
        clear_cache.assert_called_once_with(request)
        clear_cache.reset_mock()
        request = rf.get('/', {'state': 'logout state'})
        request.user = MagicMock(is_authenticated=False)
        session = sf(request)
        session[constants.SESSION_LOGOUT_STATE] = 'logout state'
        assert view.logout_callback(request, '/next', '/fail') == '/next'
        assert request.session.session_key is not None
        assert constants.SESSION_LOGOUT_STATE not in request.session
        auth.logout.assert_not_called()
        clear_cache.assert_called_once_with(request)


class TestLogoutView:
    def test_get_next_and_failure_url(self, rf, settings):
        view = LogoutView()
        settings.OIDC_REDIRECT_OK_FIELD_NAME = 'ok'
        settings.OIDC_REDIRECT_ERROR_FIELD_NAME = 'ko'
        with pytest.raises(BadRequestException, match=escape("ok parameter is required")):
            view.get_next_and_failure_url(rf.get('/'))
        with pytest.raises(BadRequestException, match=escape("ko parameter is required")):
            view.get_next_and_failure_url(rf.get('/', {'ok': '/next'}))
        assert view.get_next_and_failure_url(rf.get('/', {'ok': '/next', 'ko': '/fail'})) == ('/next', '/fail')

    @patch('oauth2_authcodeflow.views.LogoutView.logout')
    @patch('oauth2_authcodeflow.views.LogoutView.get_next_and_failure_url')
    def test_get(self, get_next_and_failure_url, logout, rf, sf):
        view = LogoutView()
        get_next_and_failure_url.side_effect = BadRequestException("bad request error")
        logout.side_effect = lambda request, id_token, next_url, failure_url: HttpResponseRedirect(next_url)
        request = rf.get('/')
        sf(request)
        response = view.get(request)
        assert response.status_code == 400
        assert response.content == b"bad request error"
        get_next_and_failure_url.assert_called_once_with(request)
        get_next_and_failure_url.reset_mock()
        get_next_and_failure_url.side_effect = None
        get_next_and_failure_url.return_value = ('/next', '/fail')
        logout.assert_not_called()
        logout.side_effect = lambda request, id_token, next_url, failure_url: HttpResponseRedirect(failure_url + '?error=some_error')
        request = rf.get('/')
        sf(request)
        response = view.get(request)
        assert response.status_code == 302
        assert response.headers['Location'] == '/fail?error=some_error'
        get_next_and_failure_url.assert_called_once_with(request)
        get_next_and_failure_url.reset_mock()
        logout.assert_called_once_with(request, None, '/next', '/fail')
        logout.reset_mock()
        logout.side_effect = lambda request, id_token, next_url, failure_url: HttpResponseRedirect(next_url)
        request = rf.get('/')
        session = sf(request)
        session[constants.SESSION_ID_TOKEN] = 'id.token'
        response = view.get(request)
        assert response.status_code == 302
        assert response.headers['Location'] == '/next'
        get_next_and_failure_url.assert_called_once_with(request)
        logout.assert_called_once_with(request, 'id.token', '/next', '/fail')

    @patch('oauth2_authcodeflow.views.LogoutView._clear_cache')
    @patch('oauth2_authcodeflow.views.auth')
    @patch('oauth2_authcodeflow.views.BlacklistedToken')
    def test_logout(self, BlacklistedToken, auth, clear_cache, rf):
        view = LogoutView()
        request = rf.get('/')
        request.user = MagicMock(is_authenticated=False)
        response = view.logout(request, 'id.token', '/next', '/fail')
        assert response.status_code == 302
        assert response.headers['Location'] == '/next'
        BlacklistedToken.blacklist.assert_called_once_with('id.token')
        BlacklistedToken.blacklist.reset_mock()
        clear_cache.assert_called_once_with(request)
        clear_cache.reset_mock()
        auth.logout.assert_not_called()
        request = rf.get('/')
        request.user = MagicMock(is_authenticated=True)
        response = view.logout(request, 'id.token', '/next', '/fail')
        assert response.status_code == 302
        assert response.headers['Location'] == '/next'
        BlacklistedToken.blacklist.assert_called_once_with('id.token')
        clear_cache.assert_called_once_with(request)
        auth.logout.assert_called_once_with(request)


class TestTotalLogoutView:
    @patch('oauth2_authcodeflow.views.LogoutView.logout')
    @patch('oauth2_authcodeflow.views.TotalLogoutView.get_url_with_params')
    @patch('oauth2_authcodeflow.views.TotalLogoutView._clear_cache')
    @patch('oauth2_authcodeflow.views.get_random_string')
    @patch('oauth2_authcodeflow.views.BlacklistedToken')
    def test_logout(self, BlacklistedToken, get_random_string, clear_cache, get_url_with_params, super_logout, db, rf, sf, settings):
        view = TotalLogoutView()
        settings.OIDC_OP_TOTAL_LOGOUT = True
        settings.OIDC_RANDOM_SIZE = 5
        get_random_string.return_value = 'abcde'
        get_url_with_params.return_value = '/callback'
        super_logout.return_value = HttpResponseRedirect('/from/super')
        request = rf.get('/')
        sf(request)
        response = view.logout(request, 'id.token', '/next', '/fail')
        assert response.status_code == 302
        assert response.headers['Location'] == '/from/super'
        BlacklistedToken.blacklist.assert_called_once_with('id.token')
        BlacklistedToken.blacklist.reset_mock()
        get_random_string.assert_not_called()
        clear_cache.assert_not_called()
        get_url_with_params.assert_not_called()
        super_logout.assert_called_once_with(request, 'id.token', '/next', '/fail')
        super_logout.reset_mock()
        request.session[constants.SESSION_OP_END_SESSION_URL] = '/end/session/url'
        response = view.logout(request, 'id.token', '/next', '/fail')
        assert response.status_code == 302
        assert response.headers['Location'] == '/callback'
        BlacklistedToken.blacklist.assert_called_once_with('id.token')
        get_random_string.assert_called_once_with(5)
        clear_cache.assert_called_once_with(request)
        get_url_with_params.assert_called_once_with(
            '/end/session/url',
            id_token_hint='id.token',
            post_logout_redirect_uri='http://testserver/oidc/callback',
            state='abcde',
        )
        assert request.session.session_key is not None


class TestLogoutByOPView:
    @patch('oauth2_authcodeflow.views.jwt')
    @patch('oauth2_authcodeflow.views.BlacklistedToken')
    def test_get(self, BlacklistedToken, jwt, rf, sf):
        view = LogoutByOPView()
        jwt.get_unverified_claims.return_value = {
            'sid': 'session.id',
        }
        request = rf.get('/')
        sf(request)
        response = view.get(request)
        assert response.status_code == 400
        assert response.content == b"sid parameter is required for logout by OP"
        BlacklistedToken.blacklist.assert_not_called()
        request = rf.get('/', {'sid': 'bad.value'})
        sf(request)
        response = view.get(request)
        assert response.status_code == 400
        assert response.content == b"missing id_token session parameter"
        BlacklistedToken.blacklist.assert_not_called()
        request = rf.get('/', {'sid': 'bad.value'})
        sf(request)
        request.session[constants.SESSION_ID_TOKEN] = 'id.token'
        response = view.get(request)
        assert response.status_code == 400
        assert response.content == b"bad sid parameter"
        BlacklistedToken.blacklist.assert_not_called()
        request = rf.get('/', {'sid': 'session.id'})
        sf(request)
        request.session[constants.SESSION_ID_TOKEN] = 'id.token'
        response = view.get(request)
        assert response.status_code == 200
        BlacklistedToken.blacklist.assert_called_once_with('id.token')
