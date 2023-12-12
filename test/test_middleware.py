from datetime import (
    datetime,
    timedelta,
    timezone,
)
from json import dumps
from re import escape
from unittest.mock import (
    MagicMock,
    patch,
)

import pytest
from django.contrib.auth import BACKEND_SESSION_KEY
from django.contrib.sessions.middleware import SessionMiddleware
from django.core.exceptions import ImproperlyConfigured
from django.http.request import HttpRequest
from django.http.response import HttpResponse
from freezegun import freeze_time

from oauth2_authcodeflow import constants
from oauth2_authcodeflow.middleware import (
    BearerAuthMiddleware,
    LoginRequiredMiddleware,
    MiddlewareException,
    Oauth2MiddlewareMixin,
    RefreshAccessTokenMiddleware,
    RefreshSessionMiddleware,
)


@pytest.fixture
def frozen_datetime():
    fake_utcnow = datetime(2023, 1, 1, tzinfo=timezone.utc)
    with freeze_time(fake_utcnow.replace(tzinfo=None)) as frozen_datetime:
        frozen_datetime.fake_utcnow = fake_utcnow
        yield frozen_datetime


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


class TestOauth2MiddlewareMixin:
    def test_init(self, settings):
        def get_response(request: HttpRequest) -> HttpResponse:
            return HttpResponse()

        def check(request: HttpResponse) -> None:
            ...

        settings.OIDC_MIDDLEWARE_NO_AUTH_URL_PATTERNS = ['/public', '/docs']
        mixin = Oauth2MiddlewareMixin(get_response, 'test', check)
        assert mixin.get_response is get_response
        assert mixin.token_type == 'test'
        assert mixin.check_function is check
        assert mixin.exempt_urls == (
            '^/oidc/authenticate',
            '^/oidc/callback',
            '^/oidc/logout',
            '^/oidc/total_logout',
            '^/oidc/logout_by_op',
            '/public',
            '/docs',
        )

    @patch('oauth2_authcodeflow.middleware.Oauth2MiddlewareMixin.process_request')
    def test_call(self, process_request, rf):
        mock_get_response = MagicMock(return_value='test_response')
        mixin = Oauth2MiddlewareMixin(mock_get_response, 'test', MagicMock())
        request = rf.get('/oidc/authenticate')
        process_request.return_value = None
        assert mixin(request) == 'test_response'
        process_request.assert_called_once_with(request)
        mock_get_response.assert_called_once_with(request)
        process_request.reset_mock()
        process_request.return_value = 'from_process_request'
        mock_get_response.reset_mock()
        assert mixin(request) == 'from_process_request'
        process_request.assert_called_once_with(request)
        mock_get_response.assert_not_called()

    def test_is_oidc_enabled(self, rf, sf):
        mixin = Oauth2MiddlewareMixin(MagicMock(), 'test', MagicMock())
        request = rf.get('/oidc/authenticate')
        session = sf(request)
        assert mixin.is_oidc_enabled(request) is False
        session[BACKEND_SESSION_KEY] = 're.Match'
        assert mixin.is_oidc_enabled(request) is False
        request.user = MagicMock(is_authenticated=False)
        assert mixin.is_oidc_enabled(request) is False
        request.user = MagicMock(is_authenticated=True)
        assert mixin.is_oidc_enabled(request) is False
        session[BACKEND_SESSION_KEY] = 'oauth2_authcodeflow.auth.AuthenticationBackend'
        assert mixin.is_oidc_enabled(request) is True
        delattr(request, 'user')
        assert mixin.is_oidc_enabled(request) is False

    @patch('oauth2_authcodeflow.middleware.Oauth2MiddlewareMixin.is_oidc_enabled')
    def test_is_refreshable_url(self, is_oidc_enabled, rf):
        mixin = Oauth2MiddlewareMixin(MagicMock(), 'test', MagicMock())
        is_oidc_enabled.return_value = False
        request = rf.get('/oidc/authenticate')
        assert mixin.is_refreshable_url(request) is False
        is_oidc_enabled.return_value = True
        assert mixin.is_refreshable_url(request) is False
        request = rf.get('/other/url')
        assert mixin.is_refreshable_url(request) is True

    @patch('oauth2_authcodeflow.middleware.BlacklistedToken')
    def test_check_blacklisted(self, BlacklistedToken, rf, sf):
        BlacklistedToken.is_blacklisted.return_value = False
        mixin = Oauth2MiddlewareMixin(MagicMock(), 'test', MagicMock())
        request = rf.get('/oidc/authenticate')
        session = sf(request)
        mixin.check_blacklisted(request)
        session[constants.SESSION_ID_TOKEN] = 'abc123'
        mixin.check_blacklisted(request)
        BlacklistedToken.is_blacklisted.return_value = True
        with pytest.raises(MiddlewareException, match=escape("token abc123 is blacklisted")):
            mixin.check_blacklisted(request)

    def test_get_next_url(self, rf, sf, settings):
        settings.OIDC_REDIRECT_OK_FIELD_NAME = 'ok'
        mixin = Oauth2MiddlewareMixin(MagicMock(), 'test', MagicMock())
        request = rf.get('/some/url')
        session = sf(request)
        assert mixin.get_next_url(request) == 'http://testserver/'
        request = rf.get('/some/url', {'ok': '/next/url'})
        session = sf(request)
        assert mixin.get_next_url(request) == 'http://testserver/next/url'
        request = rf.post('/some/api')
        session = sf(request)
        assert mixin.get_next_url(request) == 'http://testserver/'
        request = rf.get('/some/api', {'ok': '/overriden/url'})
        session = sf(request)
        session[constants.SESSION_NEXT_URL] = '/next/url'
        assert mixin.get_next_url(request) == 'http://testserver/overriden/url'
        request = rf.post('/some/api')
        session = sf(request)
        session[constants.SESSION_NEXT_URL] = 'http://otherserver/next/url'
        assert mixin.get_next_url(request) == 'http://otherserver/next/url'

    def test_get_failure_url(self, rf, sf, settings):
        settings.OIDC_REDIRECT_ERROR_FIELD_NAME = 'ko'
        mixin = Oauth2MiddlewareMixin(MagicMock(), 'test', MagicMock())
        request = rf.get('/some/url')
        session = sf(request)
        assert mixin.get_failure_url(request) == 'http://testserver/'
        session[constants.SESSION_FAIL_URL] = '/fail/url'
        assert mixin.get_failure_url(request) == 'http://testserver/fail/url'
        request = rf.get('/some/url', {'ko': '/failure/url'})
        session = sf(request)
        session[constants.SESSION_FAIL_URL] = '/fail/url'
        assert mixin.get_failure_url(request) == 'http://testserver/failure/url'
        request = rf.get('/some/api', {'ko': '/overriden/url'})
        session = sf(request)
        assert mixin.get_failure_url(request) == 'http://testserver/overriden/url'
        request = rf.post('/some/api')
        session = sf(request)
        session[constants.SESSION_FAIL_URL] = 'http://otherserver/fail/url'
        assert mixin.get_failure_url(request) == 'http://otherserver/fail/url'

    def test_destroy_session(self, rf, sf, db):
        request = rf.get('/some/url')
        session = sf(request)
        mixin = Oauth2MiddlewareMixin(MagicMock(), 'test', MagicMock())
        mixin.destroy_session(request)
        session.save()
        mixin.destroy_session(request)

    def test_is_api_request(self, rf, sf, settings):
        settings.OIDC_MIDDLEWARE_API_URL_PATTERNS = ['/rest', '/api']
        mixin = Oauth2MiddlewareMixin(MagicMock(), 'test', MagicMock())
        assert mixin.is_api_request(request=rf.get('/some/url')) is False
        assert mixin.is_api_request(request=rf.get('/api/url')) is True

    def test_json_401(self, rf):
        mixin = Oauth2MiddlewareMixin(MagicMock(), 'test', MagicMock())
        resp = mixin.json_401(rf.get('/'), 'my message')
        assert resp.status_code == 401
        assert resp.content == dumps({'error': 'my message', 'token_type': 'test'}).encode('utf8')

    def test_re_authent(self, rf, settings):
        settings.OIDC_REDIRECT_OK_FIELD_NAME = 'ok'
        settings.OIDC_REDIRECT_ERROR_FIELD_NAME = 'ko'
        mixin = Oauth2MiddlewareMixin(MagicMock(), 'test', MagicMock())
        resp = mixin.re_authent(rf.get('/'), '/next', '/fail')
        assert resp.status_code == 302
        assert resp.url == '/oidc/authenticate?ok=%2Fnext&ko=%2Ffail'

    @patch('oauth2_authcodeflow.middleware.Oauth2MiddlewareMixin.re_authent')
    @patch('oauth2_authcodeflow.middleware.Oauth2MiddlewareMixin.json_401')
    @patch('oauth2_authcodeflow.middleware.Oauth2MiddlewareMixin.is_api_request')
    def test_re_authent_or_401(self, is_api_request, json_401, re_authent, rf):
        is_api_request.return_value = False
        json_401.return_value = '401'
        re_authent.return_value = 'authent'
        mixin = Oauth2MiddlewareMixin(MagicMock(), 'test', MagicMock())
        request = rf.get('/')
        assert mixin.re_authent_or_401(request, 'test error', '/next', '/fail') == 'authent'
        is_api_request.assert_called_once_with(request)
        json_401.assert_not_called()
        re_authent.assert_called_once_with(request, '/next', '/fail')
        is_api_request.return_value = True
        is_api_request.reset_mock()
        json_401.reset_mock()
        re_authent.reset_mock()
        assert mixin.re_authent_or_401(request, 'test error', '/next', '/fail') == '401'
        is_api_request.assert_called_once_with(request)
        json_401.assert_called_once_with(request, 'test error')
        re_authent.assert_not_called()

    @patch('oauth2_authcodeflow.middleware.Oauth2MiddlewareMixin.re_authent_or_401')
    @patch('oauth2_authcodeflow.middleware.Oauth2MiddlewareMixin.destroy_session')
    @patch('oauth2_authcodeflow.middleware.Oauth2MiddlewareMixin.get_failure_url')
    @patch('oauth2_authcodeflow.middleware.Oauth2MiddlewareMixin.get_next_url')
    @patch('oauth2_authcodeflow.middleware.Oauth2MiddlewareMixin.check_blacklisted')
    def test_process_request(self, check_blacklisted, get_next_url, get_failure_url, destroy_session, re_authent_or_401, rf):
        get_next_url.return_value = '/next'
        get_failure_url.return_value = '/fail'
        re_authent_or_401.return_value = 're_authent_response'
        mixin = Oauth2MiddlewareMixin(MagicMock(), 'test', None)
        request = rf.get('/')
        resp = mixin.process_request(request)
        assert resp is None
        check_blacklisted.assert_called_once_with(request)
        get_next_url.assert_not_called()
        get_failure_url.assert_not_called()
        destroy_session.assert_not_called()
        re_authent_or_401.assert_not_called()
        check_blacklisted.reset_mock()
        check_function = MagicMock(side_effect=MiddlewareException("not good"))
        mixin = Oauth2MiddlewareMixin(MagicMock(), 'test', check_function)
        resp = mixin.process_request(request)
        assert resp == 're_authent_response'
        check_blacklisted.assert_called_once_with(request)
        check_function.assert_called_once_with(request)
        get_next_url.assert_called_once_with(request)
        get_failure_url.assert_called_once_with(request)
        destroy_session.assert_called_once_with(request)
        re_authent_or_401.assert_called_once_with(request, "not good", '/next', '/fail')


class TestLoginRequiredMiddleware:
    def test_init(self):
        get_response = MagicMock()
        middleware = LoginRequiredMiddleware(get_response)
        assert middleware.get_response is get_response
        assert middleware.token_type == 'id_token'
        assert middleware.check_function == middleware.check_login_required

    def test_is_login_required_for_url(self, rf, settings):
        settings.OIDC_MIDDLEWARE_NO_AUTH_URL_PATTERNS = ['/docs', '/public']
        middleware = LoginRequiredMiddleware(MagicMock())
        assert middleware.is_login_required_for_url(rf.get('/api/url')) is True
        assert middleware.is_login_required_for_url(rf.get('/public/who_are_we.html')) is False

    def test_is_api_request(self, rf, settings):
        settings.OIDC_MIDDLEWARE_API_URL_PATTERNS = ['/api']
        settings.OIDC_MIDDLEWARE_LOGIN_REQUIRED_REDIRECT = False
        middleware = LoginRequiredMiddleware(MagicMock())
        assert middleware.is_api_request(rf.get('/api/url')) is True
        assert middleware.is_api_request(rf.post('/api/url')) is True
        assert middleware.is_api_request(rf.get('/public/who_are_we.html')) is True
        assert middleware.is_api_request(rf.post('/public/contact_form.html')) is True
        settings.OIDC_MIDDLEWARE_LOGIN_REQUIRED_REDIRECT = True
        assert middleware.is_api_request(rf.get('/api/url')) is False
        assert middleware.is_api_request(rf.post('/api/url')) is True
        assert middleware.is_api_request(rf.get('/public/who_are_we.html')) is False
        assert middleware.is_api_request(rf.post('/public/contact_form.html')) is False

    @patch('oauth2_authcodeflow.middleware.authenticate')
    @patch('oauth2_authcodeflow.middleware.LoginRequiredMiddleware.is_login_required_for_url')
    def test_check_login_required(self, is_login_required_for_url, authenticate, rf, sf):
        is_login_required_for_url.return_value = False
        authenticate.return_value = 'a user'
        request = rf.get('/')
        session = sf(request)
        middleware = LoginRequiredMiddleware(MagicMock())
        middleware.check_login_required(request)
        request.user = MagicMock(is_authenticated=True)
        middleware.check_login_required(request)
        request.user = MagicMock(is_authenticated=False)
        middleware.check_login_required(request)
        delattr(request, 'user')
        middleware.check_login_required(request)
        is_login_required_for_url.return_value = True
        session[constants.SESSION_ID_TOKEN] = 'abc123'
        middleware.check_login_required(request)
        del session[constants.SESSION_ID_TOKEN]
        middleware.check_login_required(request)
        authenticate.return_value = None
        with pytest.raises(MiddlewareException, match=escape("id token is missing, user is not authenticated")):
            middleware.check_login_required(request)
        authenticate.side_effect = ValueError("some error")
        with pytest.raises(MiddlewareException, match=escape("some error")):
            middleware.check_login_required(request)


class TestRefreshAccessTokenMiddleware:
    def test_init(self):
        get_response = MagicMock()
        middleware = RefreshAccessTokenMiddleware(get_response)
        assert middleware.get_response is get_response
        assert middleware.token_type == 'access_token'
        assert middleware.check_function == middleware.check_access_token

    @patch('oauth2_authcodeflow.middleware.RefreshAccessTokenMiddleware.is_refreshable_url')
    @patch('oauth2_authcodeflow.middleware.BlacklistedToken')
    @patch('oauth2_authcodeflow.middleware.request_post')
    def test_check_access_token(self, request_post, BlacklistedToken, is_refreshable_url, db, rf, sf, frozen_datetime, settings):
        settings.OIDC_RP_CLIENT_ID = 'client_id'
        settings.OIDC_RP_CLIENT_SECRET = 'client_secret'
        request_post.return_value.json.return_value = {
            'access_token': '456789',
            'expires_in': 120,
        }
        request_post.return_value.text = "some error"
        is_refreshable_url.return_value = False
        request = rf.get('/')
        session = sf(request)
        session[constants.SESSION_ID_TOKEN] = 'abc123'
        middleware = RefreshAccessTokenMiddleware(MagicMock())
        middleware.check_access_token(request)
        assert session.session_key is None
        is_refreshable_url.return_value = True
        session = sf(request)
        session[constants.SESSION_ID_TOKEN] = 'abc123'
        middleware.check_access_token(request)
        assert session.session_key is None
        expires_at = (datetime.now(timezone.utc) + timedelta(seconds=20)).timestamp()
        session = sf(request)
        session[constants.SESSION_ID_TOKEN] = 'abc123'
        session[constants.SESSION_REFRESH_TOKEN] = '13579'
        session[constants.SESSION_ACCESS_TOKEN] = '123456'
        session[constants.SESSION_ACCESS_EXPIRES_AT] = expires_at
        session[constants.SESSION_OP_TOKEN_URL] = 'token_url'
        middleware.check_access_token(request)
        assert session.session_key is None
        expires_at = (datetime.now(timezone.utc) - timedelta(seconds=20)).timestamp()
        expected_expires_at = (datetime.now(timezone.utc) + timedelta(seconds=120)).timestamp()
        session = sf(request)
        session[constants.SESSION_ID_TOKEN] = 'abc123'
        session[constants.SESSION_REFRESH_TOKEN] = '13579'
        session[constants.SESSION_ACCESS_TOKEN] = '123456'
        session[constants.SESSION_ACCESS_EXPIRES_AT] = expires_at
        session[constants.SESSION_OP_TOKEN_URL] = 'token_url'
        middleware.check_access_token(request)
        assert session.session_key is not None
        assert session[constants.SESSION_ID_TOKEN] == 'abc123'
        assert session[constants.SESSION_ACCESS_TOKEN] == '456789'
        assert session[constants.SESSION_ACCESS_EXPIRES_AT] == expected_expires_at
        assert session[constants.SESSION_REFRESH_TOKEN] == '13579'
        BlacklistedToken.blacklist.assert_not_called()
        session = sf(request)
        session[constants.SESSION_ID_TOKEN] = 'abc123'
        session[constants.SESSION_REFRESH_TOKEN] = '13579'
        session[constants.SESSION_ACCESS_TOKEN] = '123456'
        session[constants.SESSION_ACCESS_EXPIRES_AT] = expires_at
        session[constants.SESSION_OP_TOKEN_URL] = 'token_url'
        request_post.return_value.json.return_value.update(id_token='abc456', refresh_token='24680')
        middleware.check_access_token(request)
        assert session.session_key is not None
        assert session[constants.SESSION_ID_TOKEN] == 'abc456'
        assert session[constants.SESSION_ACCESS_TOKEN] == '456789'
        assert session[constants.SESSION_ACCESS_EXPIRES_AT] == expected_expires_at
        assert session[constants.SESSION_REFRESH_TOKEN] == '24680'
        BlacklistedToken.blacklist.assert_called_once_with('abc123')
        request_post.return_value.__bool__.return_value = False
        session = sf(request)
        session[constants.SESSION_ID_TOKEN] = 'abc123'
        session[constants.SESSION_REFRESH_TOKEN] = '13579'
        session[constants.SESSION_ACCESS_TOKEN] = '123456'
        session[constants.SESSION_ACCESS_EXPIRES_AT] = expires_at
        session[constants.SESSION_OP_TOKEN_URL] = 'token_url'
        with pytest.raises(MiddlewareException, match=escape("some error")):
            middleware.check_access_token(request)


class TestRefreshSessionMiddleware:
    def test_init(self, settings):
        get_response = MagicMock()
        middleware = RefreshSessionMiddleware(get_response)
        assert middleware.get_response is get_response
        assert middleware.token_type == 'refresh_token'
        assert middleware.check_function == middleware.check_session
        settings.SESSION_COOKIE_AGE = 1800
        settings.OIDC_MIDDLEWARE_SESSION_TIMEOUT_SECONDS = 3600
        with pytest.raises(ImproperlyConfigured, match=escape(
            "OIDC_MIDDLEWARE_SESSION_TIMEOUT_SECONDS should be less than SESSION_COOKIE_AGE"
            " and more than 10 seconds"
        )):
            RefreshSessionMiddleware(get_response)
        settings.OIDC_MIDDLEWARE_SESSION_TIMEOUT_SECONDS = 5
        with pytest.raises(ImproperlyConfigured, match=escape(
            "OIDC_MIDDLEWARE_SESSION_TIMEOUT_SECONDS should be less than SESSION_COOKIE_AGE"
            " and more than 10 seconds"
        )):
            RefreshSessionMiddleware(get_response)
        settings.OIDC_MIDDLEWARE_SESSION_TIMEOUT_SECONDS = 30
        RefreshSessionMiddleware(get_response)

    @patch('oauth2_authcodeflow.middleware.RefreshSessionMiddleware.is_refreshable_url')
    @patch('oauth2_authcodeflow.middleware.BlacklistedToken')
    def test_check_session(self, BlacklistedToken, is_refreshable_url, rf, sf, frozen_datetime):
        is_refreshable_url.return_value = False
        expires_at = (datetime.now(timezone.utc) + timedelta(seconds=20)).timestamp()
        request = rf.get('/')
        session = sf(request)
        session[constants.SESSION_ID_TOKEN] = 'abc123'
        session[constants.SESSION_EXPIRES_AT] = expires_at
        middleware = RefreshSessionMiddleware(MagicMock())
        middleware.check_session(request)
        BlacklistedToken.blacklist.assert_not_called()
        is_refreshable_url.return_value = True
        middleware.check_session(request)
        with pytest.raises(MiddlewareException, match=escape(f"No {constants.SESSION_EXPIRES_AT} parameter in the backend session")):
            session = sf(request)
            session[constants.SESSION_ID_TOKEN] = 'abc123'
            middleware.check_session(request)
            BlacklistedToken.blacklist.assert_not_called()
        with pytest.raises(MiddlewareException, match=escape("Session has expired")):
            expires_at = (datetime.now(timezone.utc) - timedelta(seconds=20)).timestamp()
            session = sf(request)
            session[constants.SESSION_ID_TOKEN] = 'abc123'
            session[constants.SESSION_EXPIRES_AT] = expires_at
            middleware.check_session(request)
            BlacklistedToken.blacklist.assert_called_once_with('abc123')


class TestBearerAuthMiddleware:
    def test_init(self):
        get_response = MagicMock()
        middleware = BearerAuthMiddleware(get_response)
        assert middleware.get_response is get_response
        assert middleware.token_type is None
        assert middleware.check_function is None

    @patch('oauth2_authcodeflow.middleware.BearerAuthenticationBackend')
    def test_process_request(self, BearerAuthenticationBackend, db, rf, sf):
        BearerAuthenticationBackend.return_value.authenticate.return_value = None
        request = rf.get('/')
        session = sf(request)
        middleware = BearerAuthMiddleware(MagicMock())
        assert middleware.process_request(request) is None
        assert session.session_key is None
        assert getattr(request, 'user', None) is None
        BearerAuthenticationBackend.assert_not_called()
        request = rf.get('/', HTTP_AUTHORIZATION='Truc Much')
        session = sf(request)
        assert middleware.process_request(request) is None
        assert session.session_key is None
        assert getattr(request, 'user', None) is None
        BearerAuthenticationBackend.assert_called_once_with()
        BearerAuthenticationBackend.return_value.authenticate.assert_called_once_with(request)
        BearerAuthenticationBackend.reset_mock()
        BearerAuthenticationBackend.return_value.authenticate.reset_mock()
        BearerAuthenticationBackend.return_value.authenticate.return_value = 'a user'
        request = rf.get('/', HTTP_AUTHORIZATION='Truc Much')
        session = sf(request)
        assert middleware.process_request(request) is None
        assert session.session_key is not None
        assert getattr(request, 'user', None) == 'a user'
        BearerAuthenticationBackend.assert_called_once_with()
        BearerAuthenticationBackend.return_value.authenticate.assert_called_once_with(request)
        request = rf.get('/', HTTP_AUTHORIZATION='Truc Much')
        session = sf(request)
        session.save()
        expected_session_key = session.session_key
        assert middleware.process_request(request) is None
        assert session.session_key == expected_session_key
        assert getattr(request, 'user', None) == 'a user'
