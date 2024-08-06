from base64 import b64encode
from datetime import (
    datetime,
    timedelta,
    timezone,
)
from json import dumps
from re import escape
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.contrib.auth.backends import ModelBackend
from django.contrib.sessions.middleware import SessionMiddleware
from django.core.exceptions import SuspiciousOperation
from freezegun import freeze_time
from jose import jwt
from jose.utils import long_to_base64

from oauth2_authcodeflow import constants
from oauth2_authcodeflow.auth import (
    AuthenticationBackend,
    AuthenticationMixin,
    BearerAuthenticationBackend,
)
from oauth2_authcodeflow.utils import OIDCUrlsMixin


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


class TestAuthenticationMixin:
    def test_user_model(self, django_user_model):
        assert AuthenticationMixin.UserModel is django_user_model

    def test_validate_and_decode_id_token_bad_data(self, frozen_datetime, settings):
        authentication = AuthenticationMixin()  # noqa
        with pytest.raises(SuspiciousOperation, match=escape("No alg value found in header")):
            authentication.validate_and_decode_id_token(
                id_token=b64encode(dumps({'typ': 'jwt'}).encode('ascii')).decode('ascii') + '.data.sign',
                nonce=None,
                jwks={},
            )
        settings.OIDC_RP_SIGN_ALGOS_ALLOWED = ['RS256', 'RS512']
        settings.OIDC_RP_CLIENT_ID = 'a_client_id'
        settings.OIDC_RP_CLIENT_SECRET = 'a_client_secret'
        rsa_private_pem = rsa.generate_private_key(65537, 2048).private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        original_claims = {
            'aud': settings.OIDC_RP_CLIENT_ID,
            'email': 'my-email@example.com',
            'exp': frozen_datetime() + timedelta(minutes=2),
            'nonce': 'bépo',
        }
        hs_token = jwt.encode(
            claims=original_claims,
            key=settings.OIDC_RP_CLIENT_SECRET,
            algorithm='HS256',
        )
        rs_token = jwt.encode(
            claims=original_claims,
            key=rsa_private_pem,
            algorithm='RS256',
            headers={'kid': '123'},
        )
        with pytest.raises(SuspiciousOperation, match=escape("The token algorithm HS256 is not allowed (RS256, RS512)")):
            authentication.validate_and_decode_id_token(
                id_token=hs_token,
                nonce=None,
                jwks={},
            )
        with pytest.raises(SuspiciousOperation, match=escape("No key found matching key id 123 and algorithm RS256")):
            authentication.validate_and_decode_id_token(
                id_token=rs_token,
                nonce=None,
                jwks={'123': {'kid': '123', 'kty': 'RSA', 'alg': 'RS512', 'use': 'sig', 'n': '5wkSa6CQ', 'e': 'AQAB'}},
            )
        with pytest.raises(SuspiciousOperation, match=escape("No key found matching key id 123 and algorithm RS256")):
            authentication.validate_and_decode_id_token(
                id_token=rs_token,
                nonce=None,
                jwks={'124': {'kid': '124', 'kty': 'RSA', 'alg': 'RS256', 'use': 'sig', 'n': '5wkSa6CQ', 'e': 'AQAB'}},
            )
        settings.OIDC_RP_SIGN_ALGOS_ALLOWED = ['HS256', 'RS256', 'EC']
        with pytest.raises(NotImplementedError, match=escape("Algo EC cannot be handled by this authentication backend")):
            authentication.validate_and_decode_id_token(
                id_token=b64encode(dumps({'alg': 'EC', 'typ': 'jwt'}).encode('ascii')).decode('ascii') + '.data.sign',
                nonce=None,
                jwks={},
            )
        settings.OIDC_RP_SIGN_ALGOS_ALLOWED = ['HS256', 'RS256']
        with pytest.raises(SuspiciousOperation, match=escape("JWT token verification failed")):
            authentication.validate_and_decode_id_token(
                id_token='.'.join(hs_token.split('.')[:2]) + '.badsign',
                nonce=None,
                jwks={},
            )
        with pytest.raises(SuspiciousOperation, match=escape("JWT Nonce verification failed")):
            authentication.validate_and_decode_id_token(
                id_token=hs_token,
                nonce='bad_nonce',
                jwks={},
            )

    def test_validate_and_decode_id_token_get_claims_with_secret(self, frozen_datetime, settings):
        settings.OIDC_RP_CLIENT_ID = 'a_client_id'
        settings.OIDC_RP_CLIENT_SECRET = 'a_client_secret'
        authentication = AuthenticationMixin()
        original_claims = {
            'aud': settings.OIDC_RP_CLIENT_ID,
            'email': 'my-email@example.com',
            'exp': frozen_datetime() + timedelta(minutes=2),
            'nonce': 'bépo',
        }
        token = jwt.encode(
            claims=original_claims,
            key=settings.OIDC_RP_CLIENT_SECRET,
            algorithm='HS256',
        )
        claims = authentication.validate_and_decode_id_token(
            id_token=token,
            nonce='bépo',
            jwks={},
        )
        assert claims == original_claims

    def test_validate_and_decode_id_token_get_claims_with_jwk_rsa(self, frozen_datetime, settings):
        rsa_private_key = rsa.generate_private_key(65537, 2048)
        rsa_private_pem = rsa_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        rsa_public_key = rsa_private_key.public_key()
        rsa_public_numbers = rsa_public_key.public_numbers()
        settings.OIDC_RP_CLIENT_ID = 'a_client_id'
        authentication = AuthenticationMixin()
        original_claims = {
            'aud': settings.OIDC_RP_CLIENT_ID,
            'email': 'my-email@example.com',
            'exp': frozen_datetime() + timedelta(minutes=2),
        }
        token = jwt.encode(
            claims=original_claims,
            key=rsa_private_pem,
            algorithm='RS256',
            headers={'kid': '123'},
        )
        claims = authentication.validate_and_decode_id_token(
            id_token=token,
            nonce=None,
            jwks={
                '42': {'kid': '42', 'kty': 'RSA', 'alg': 'RS256', 'use': 'sig'},
                '123': {
                    'kid': '123', 'kty': 'RSA', 'alg': 'RS256', 'use': 'sig',
                    'n': long_to_base64(rsa_public_numbers.n),
                    'e': long_to_base64(rsa_public_numbers.e),
                },
            },
        )
        assert claims == original_claims

    def test_validate_and_decode_id_token_get_claims_with_settings_rsa(self, frozen_datetime, settings):
        rsa_private_key = rsa.generate_private_key(65537, 2048)
        rsa_private_pem = rsa_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        rsa_public_key = rsa_private_key.public_key()
        rsa_public_pem = rsa_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.PKCS1,
        )
        settings.OIDC_RP_CLIENT_ID = 'a_client_id'
        settings.OIDC_RP_IDP_SIGN_KEY = rsa_public_pem
        authentication = AuthenticationMixin()
        original_claims = {
            'aud': settings.OIDC_RP_CLIENT_ID,
            'email': 'my-email@example.com',
            'exp': frozen_datetime() + timedelta(minutes=2),
        }
        token = jwt.encode(
            claims=original_claims,
            key=rsa_private_pem,
            algorithm='RS256',
            headers={'kid': '123'},
        )
        claims = authentication.validate_and_decode_id_token(
            id_token=token,
            nonce=None,
            jwks={},
        )
        assert claims == original_claims

    def test_validate_claims(self, settings):
        authentication = AuthenticationMixin()
        with pytest.raises(SuspiciousOperation, match=escape("'email' claim was expected")):
            authentication.validate_claims({})
        settings.OIDC_OP_EXPECTED_EMAIL_CLAIM = 'e-mail'
        settings.OIDC_OP_EXPECTED_CLAIMS = ['FirstName', 'LastName']
        claims = {'Email': 'test@example.com', 'FirstName': 'Cyrille'}
        with pytest.raises(SuspiciousOperation, match=escape("'e-mail' claim was expected")):
            authentication.validate_claims(claims)
        settings.OIDC_OP_EXPECTED_EMAIL_CLAIM = 'Email'
        with pytest.raises(SuspiciousOperation, match=escape("'LastName' claim was expected")):
            authentication.validate_claims(claims)
        claims.update({'LastName': 'Pontvieux'})
        authentication.validate_claims(claims)

    @patch('oauth2_authcodeflow.auth.request_get')
    def test_get_or_create_user(self, request_get, db, rf, sf, settings):
        authentication = AuthenticationMixin()
        request = rf.get('/oidc/authenticate')
        session = sf(request)
        claims = {'username': 'test_cyrille'}
        access_token = 'a_token'
        settings.OIDC_DJANGO_USERNAME_FUNC = lambda claims: claims['username']
        settings.OIDC_OP_FETCH_USER_INFO = False
        settings.OIDC_OP_EXPECTED_EMAIL_CLAIM = 'email'
        settings.OIDC_FIRSTNAME_CLAIM = 'first_name'
        settings.OIDC_LASTNAME_CLAIM = 'last_name'
        session[constants.SESSION_OP_USERINFO_URL] = 'userinfo_url'
        session.save()
        settings.OIDC_AUTHORIZATION_HEADER_PREFIX = 'Bearer'
        request_get.return_value.json.return_value = {
            settings.OIDC_OP_EXPECTED_EMAIL_CLAIM: 'test@example.com',
            settings.OIDC_FIRSTNAME_CLAIM: 'Cyrille',
            settings.OIDC_LASTNAME_CLAIM: 'Pontvieux',
        }
        user = authentication.get_or_create_user(request, claims, access_token)
        assert user
        assert user.id
        assert user.username == 'test_cyrille'
        assert user.email == ''
        assert user.first_name == ''
        assert user.last_name == ''
        assert user.is_active is True
        assert user.has_usable_password() is False
        user.set_password('test')
        user.save()
        request_get.assert_not_called()
        request_get.reset_mock()
        settings.OIDC_OP_FETCH_USER_INFO = True
        user2 = authentication.get_or_create_user(request, claims, access_token)
        request_get.assert_called_once_with('userinfo_url', headers={'Authorization': 'Bearer a_token'})
        request_get.reset_mock()
        assert user2
        assert user2.id == user.id
        assert user2.username == 'test_cyrille'
        assert user2.email == 'test@example.com'
        assert user2.first_name == 'Cyrille'
        assert user2.last_name == 'Pontvieux'
        assert user2.is_active is True
        assert user2.has_usable_password() is False

        def extend_user(user, claims, request, access_token):
            user.is_staff = claims.get('staff', 'no') == 'yes'

        def extend_user_compat(user, claims):
            extend_user(user, claims, None, None)

        settings.OIDC_EMAIL_CLAIM = lambda claims: claims['username'] + '@example.com'
        settings.OIDC_FIRSTNAME_CLAIM = lambda claims: claims['username'].split('.')[0]
        settings.OIDC_LASTNAME_CLAIM = lambda claims: claims['username'].split('.')[1]
        settings.OIDC_UNUSABLE_PASSWORD = False
        settings.OIDC_EXTEND_USER = extend_user
        claims2 = {'username': 'cyrille.pontvieux', 'e-mail': 'cyrille@example.com'}
        user3 = authentication.get_or_create_user(request, claims2, access_token)
        assert user3
        assert user3.id
        assert user3.username == 'cyrille.pontvieux'
        assert user3.email == 'cyrille.pontvieux@example.com'
        assert user3.first_name == 'cyrille'
        assert user3.last_name == 'pontvieux'
        assert user3.is_active is True
        assert user3.has_usable_password() is False
        user3.set_password('test')
        user3.save()
        settings.OIDC_EMAIL_CLAIM = 'e-mail'
        settings.OIDC_EXTEND_USER = extend_user_compat
        user4 = authentication.get_or_create_user(request, claims2, access_token)
        assert user4
        assert user4.id == user3.id
        assert user4.username == 'cyrille.pontvieux'
        assert user4.email == 'cyrille@example.com'
        assert user4.first_name == 'cyrille'
        assert user4.last_name == 'pontvieux'
        assert user4.is_active is True
        assert user4.has_usable_password() is True


class TestAuthenticationBackend:
    @patch('oauth2_authcodeflow.auth.AuthenticationBackend.authenticate_oauth2')
    def test_authenticate_no_action(self, authenticate_oauth2, rf, settings):
        authenticate_oauth2.return_value = 'a user'
        authentication = AuthenticationBackend()
        assert isinstance(authentication, AuthenticationMixin)
        assert isinstance(authentication, ModelBackend)
        settings.OIDC_MIDDLEWARE_NO_AUTH_URL_PATTERNS = ['/public', '/docs']
        request = rf.get('/public/who_are_we.html')
        assert authentication.authenticate(request) is None
        authenticate_oauth2.assert_not_called()
        request = rf.get('/api/protected_resource')
        assert authentication.authenticate(request, username='not used', password='by this backend') is None
        authenticate_oauth2.assert_not_called()

    @patch('oauth2_authcodeflow.auth.AuthenticationBackend.authenticate_oauth2')
    def test_authenticate_proxied_to_oauth2_method(self, authenticate_oauth2, rf, settings):
        authenticate_oauth2.return_value = 'a user'
        authentication = AuthenticationBackend()
        settings.OIDC_MIDDLEWARE_NO_AUTH_URL_PATTERNS = ['/public', '/docs']
        request = rf.get('/api/protected_resource')
        assert authentication.authenticate(request, use_pkce=True, code='code', state='state', nonce='nonce', code_verifier='code_verifier') == 'a user'
        authenticate_oauth2.assert_called_once_with(request, True, 'code', 'state', 'nonce', 'code_verifier')

    @patch('oauth2_authcodeflow.auth.request_post')
    def test_authenticate_oauth2_return_none(self, request_post, frozen_datetime, caplog, db, rf, sf, settings):
        request_post.return_value.status_code = 400
        request_post.return_value.json.return_value = {
            'id_token': 'ID_TOKEN',
            'access_token': 'ACCESS_TOKEN',
        }
        settings.OIDC_RP_CLIENT_ID = 'a_client_id'
        settings.OIDC_RP_CLIENT_SECRET = 'a_client_secret'
        settings.OIDC_RP_SCOPES = ['openid', 'email', 'profile', 'offline_access']
        settings.OIDC_MIDDLEWARE_SESSION_TIMEOUT_SECONDS = 7 * 86400
        authentication = AuthenticationBackend()
        request = rf.get('/api/protected_resource')
        session = sf(request)
        session[constants.SESSION_OP_TOKEN_URL] = 'token_url'
        session.save()
        request.build_absolute_uri = lambda uri: uri
        assert authentication.authenticate_oauth2(None, False, '', None, None, None) is None
        assert authentication.authenticate_oauth2(request, False, '', None, None, None) is None
        assert authentication.authenticate_oauth2(request, False, 'code', None, None, None) is None
        assert authentication.authenticate_oauth2(request, False, 'code', 'state', None, None) is None
        assert authentication.authenticate_oauth2(request, True, '', 'state', 'nonce', 'verifier') is None
        assert authentication.authenticate_oauth2(request, True, 'code', 'state', 'nonce', None) is None
        assert authentication.authenticate_oauth2(request, True, 'code', 'state', 'nonce', 'verifier') is None
        request_post.assert_called_once_with(
            'token_url',
            data={
                'grant_type': 'authorization_code',
                'client_id': settings.OIDC_RP_CLIENT_ID,
                'client_secret': settings.OIDC_RP_CLIENT_SECRET,
                'redirect_uri': '/oidc/callback',
                'code': 'code',
                'code_verifier': 'verifier',
            },
            headers={'origin': '/oidc/callback'},
        )

    @patch('oauth2_authcodeflow.auth.AuthenticationBackend.get_or_create_user')
    @patch('oauth2_authcodeflow.auth.AuthenticationBackend.validate_claims')
    @patch('oauth2_authcodeflow.auth.AuthenticationBackend.validate_and_decode_id_token')
    @patch('oauth2_authcodeflow.auth.request_post')
    def test_authenticate_oauth2_return_user_with_pkce_no_refresh(
        self, request_post, validate_and_decode_id_token, validate_claims, get_or_create_user,
        frozen_datetime, caplog, db, rf, sf, settings
    ):
        request_post.return_value.status_code = 200
        request_post.return_value.json.return_value = {
            'id_token': 'ID_TOKEN',
            'access_token': 'ACCESS_TOKEN',
        }
        settings.OIDC_RP_CLIENT_ID = 'a_client_id'
        settings.OIDC_RP_CLIENT_SECRET = 'a_client_secret'
        settings.OIDC_RP_SCOPES = ['openid', 'email', 'profile', 'offline_access']
        settings.OIDC_MIDDLEWARE_SESSION_TIMEOUT_SECONDS = 7 * 86400
        access_expires_at = int(frozen_datetime.fake_utcnow.timestamp()) + 2 * 60
        claims = {
            'aud': settings.OIDC_RP_CLIENT_ID,
            'email': 'my-email@example.com',
            'exp': access_expires_at,
        }
        validate_and_decode_id_token.return_value = claims
        get_or_create_user.return_value = 'user'
        authentication = AuthenticationBackend()
        request = rf.get('/api/protected_resource')
        session = sf(request)
        session[constants.SESSION_OP_TOKEN_URL] = 'token_url'
        session.save()
        request.build_absolute_uri = lambda uri: uri
        assert authentication.authenticate_oauth2(request, True, 'code', 'state', 'nonce', 'verifier') == 'user'
        request_post.assert_called_once_with(
            'token_url',
            data={
                'grant_type': 'authorization_code',
                'client_id': settings.OIDC_RP_CLIENT_ID,
                'client_secret': settings.OIDC_RP_CLIENT_SECRET,
                'redirect_uri': '/oidc/callback',
                'code': 'code',
                'code_verifier': 'verifier',
            },
            headers={'origin': '/oidc/callback'},
        )
        assert dict(session.items()) == {
            constants.SESSION_OP_TOKEN_URL: 'token_url',
            constants.SESSION_ID_TOKEN: 'ID_TOKEN',
            constants.SESSION_ACCESS_TOKEN: 'ACCESS_TOKEN',
            constants.SESSION_ACCESS_EXPIRES_AT: access_expires_at,
            constants.SESSION_EXPIRES_AT: int(frozen_datetime.fake_utcnow.timestamp()) + 7 * 86400,
        }
        validate_and_decode_id_token.assert_called_once_with('ID_TOKEN', 'nonce', {})
        validate_claims.assert_called_once_with(claims)
        get_or_create_user.assert_called_once_with(request, claims, 'ACCESS_TOKEN')

    @patch('oauth2_authcodeflow.auth.AuthenticationBackend.get_or_create_user')
    @patch('oauth2_authcodeflow.auth.AuthenticationBackend.validate_claims')
    @patch('oauth2_authcodeflow.auth.AuthenticationBackend.validate_and_decode_id_token')
    @patch('oauth2_authcodeflow.auth.request_post')
    def test_authenticate_oauth2_return_user_with_pkce_no_secret(
        self, request_post, validate_and_decode_id_token, validate_claims, get_or_create_user,
        frozen_datetime, caplog, db, rf, sf, settings
    ):
        request_post.return_value.status_code = 200
        request_post.return_value.json.return_value = {
            'id_token': 'ID_TOKEN',
            'access_token': 'ACCESS_TOKEN',
        }
        settings.OIDC_RP_CLIENT_ID = 'a_client_id'
        settings.OIDC_RP_CLIENT_SECRET = ''
        settings.OIDC_RP_SCOPES = ['openid', 'email', 'profile', 'offline_access']
        settings.OIDC_MIDDLEWARE_SESSION_TIMEOUT_SECONDS = 7 * 86400
        access_expires_at = int(frozen_datetime.fake_utcnow.timestamp()) + 2 * 60
        claims = {
            'aud': settings.OIDC_RP_CLIENT_ID,
            'email': 'my-email@example.com',
            'exp': access_expires_at,
        }
        validate_and_decode_id_token.return_value = claims
        get_or_create_user.return_value = 'user'
        authentication = AuthenticationBackend()
        request = rf.get('/api/protected_resource')
        session = sf(request)
        session[constants.SESSION_OP_TOKEN_URL] = 'token_url'
        session.save()
        request.build_absolute_uri = lambda uri: uri
        assert authentication.authenticate_oauth2(request, True, 'code', 'state', 'nonce', 'verifier') == 'user'
        request_post.assert_called_once_with(
            'token_url',
            data={
                'grant_type': 'authorization_code',
                'client_id': settings.OIDC_RP_CLIENT_ID,
                'redirect_uri': '/oidc/callback',
                'code': 'code',
                'code_verifier': 'verifier',
            },
            headers={'origin': '/oidc/callback'},
        )
        assert dict(session.items()) == {
            constants.SESSION_OP_TOKEN_URL: 'token_url',
            constants.SESSION_ID_TOKEN: 'ID_TOKEN',
            constants.SESSION_ACCESS_TOKEN: 'ACCESS_TOKEN',
            constants.SESSION_ACCESS_EXPIRES_AT: access_expires_at,
            constants.SESSION_EXPIRES_AT: int(frozen_datetime.fake_utcnow.timestamp()) + 7 * 86400,
        }
        validate_and_decode_id_token.assert_called_once_with('ID_TOKEN', 'nonce', {})
        validate_claims.assert_called_once_with(claims)
        get_or_create_user.assert_called_once_with(request, claims, 'ACCESS_TOKEN')

    @patch('oauth2_authcodeflow.auth.AuthenticationBackend.get_or_create_user')
    @patch('oauth2_authcodeflow.auth.AuthenticationBackend.validate_claims')
    @patch('oauth2_authcodeflow.auth.AuthenticationBackend.validate_and_decode_id_token')
    @patch('oauth2_authcodeflow.auth.request_post')
    def test_authenticate_oauth2_return_user_with_pkce_with_refresh_and_exp(
        self, request_post, validate_and_decode_id_token, validate_claims, get_or_create_user,
        frozen_datetime, caplog, db, rf, sf, settings
    ):
        request_post.return_value.status_code = 200
        request_post.return_value.json.return_value = {
            'id_token': 'ID_TOKEN',
            'access_token': 'ACCESS_TOKEN',
            'expires_in': 3 * 60,
            'refresh_token': 'REFRESH_TOKEN',
        }
        settings.OIDC_RP_CLIENT_ID = 'a_client_id'
        settings.OIDC_RP_CLIENT_SECRET = 'a_client_secret'
        settings.OIDC_RP_SCOPES = ['openid', 'email', 'profile', 'offline_access']
        settings.OIDC_MIDDLEWARE_SESSION_TIMEOUT_SECONDS = 7 * 86400
        access_expires_at = int(frozen_datetime.fake_utcnow.timestamp()) + 2 * 60
        validate_and_decode_id_token.return_value = {
            'aud': settings.OIDC_RP_CLIENT_ID,
            'email': 'my-email@example.com',
            'exp': access_expires_at,
        }
        get_or_create_user.return_value = 'user'
        authentication = AuthenticationBackend()
        request = rf.get('/api/protected_resource')
        session = sf(request)
        session[constants.SESSION_OP_TOKEN_URL] = 'token_url'
        session[constants.SESSION_OP_JWKS] = {'key_id': 'some_key'}
        session.save()
        request.build_absolute_uri = lambda uri: uri
        assert authentication.authenticate_oauth2(request, True, 'code', 'state', 'nonce', 'verifier') == 'user'
        request_post.assert_called_once_with(
            'token_url',
            data={
                'grant_type': 'authorization_code',
                'client_id': settings.OIDC_RP_CLIENT_ID,
                'client_secret': settings.OIDC_RP_CLIENT_SECRET,
                'redirect_uri': '/oidc/callback',
                'code': 'code',
                'code_verifier': 'verifier',
            },
            headers={'origin': '/oidc/callback'},
        )
        assert dict(session.items()) == {
            constants.SESSION_OP_TOKEN_URL: 'token_url',
            constants.SESSION_OP_JWKS: {'key_id': 'some_key'},
            constants.SESSION_ID_TOKEN: 'ID_TOKEN',
            constants.SESSION_ACCESS_TOKEN: 'ACCESS_TOKEN',
            constants.SESSION_ACCESS_EXPIRES_AT: int(frozen_datetime.fake_utcnow.timestamp()) + 3 * 60,
            constants.SESSION_EXPIRES_AT: int(frozen_datetime.fake_utcnow.timestamp()) + 7 * 86400,
            constants.SESSION_REFRESH_TOKEN: 'REFRESH_TOKEN',
        }

    @patch('oauth2_authcodeflow.auth.AuthenticationBackend.get_or_create_user')
    @patch('oauth2_authcodeflow.auth.AuthenticationBackend.validate_claims')
    @patch('oauth2_authcodeflow.auth.AuthenticationBackend.validate_and_decode_id_token')
    @patch('oauth2_authcodeflow.auth.request_post')
    def test_authenticate_oauth2_return_user_without_pkce(
        self, request_post, validate_and_decode_id_token, validate_claims, get_or_create_user,
        frozen_datetime, caplog, db, rf, sf, settings
    ):
        request_post.return_value.status_code = 200
        request_post.return_value.json.return_value = {
            'id_token': 'ID_TOKEN',
            'access_token': 'ACCESS_TOKEN',
        }
        settings.OIDC_RP_CLIENT_ID = 'a_client_id'
        settings.OIDC_RP_CLIENT_SECRET = 'a_client_secret'
        settings.OIDC_RP_SCOPES = ['openid', 'email', 'profile']
        settings.OIDC_MIDDLEWARE_SESSION_TIMEOUT_SECONDS = 7 * 86400
        validate_and_decode_id_token.return_value = {
            'aud': settings.OIDC_RP_CLIENT_ID,
            'email': 'my-email@example.com',
        }
        get_or_create_user.return_value = 'user'
        authentication = AuthenticationBackend()
        request = rf.get('/api/protected_resource')
        session = sf(request)
        session[constants.SESSION_OP_TOKEN_URL] = 'token_url'
        session.save()
        request.build_absolute_uri = lambda uri: uri
        assert authentication.authenticate_oauth2(request, False, 'code', 'state', 'nonce', None) == 'user'
        request_post.assert_called_once_with(
            'token_url',
            data={
                'grant_type': 'authorization_code',
                'client_id': settings.OIDC_RP_CLIENT_ID,
                'client_secret': settings.OIDC_RP_CLIENT_SECRET,
                'redirect_uri': '/oidc/callback',
                'code': 'code',
            },
            headers={'origin': '/oidc/callback'},
        )
        assert dict(session.items()) == {
            constants.SESSION_OP_TOKEN_URL: 'token_url',
            constants.SESSION_ID_TOKEN: 'ID_TOKEN',
            constants.SESSION_ACCESS_TOKEN: 'ACCESS_TOKEN',
            constants.SESSION_ACCESS_EXPIRES_AT: int(frozen_datetime.fake_utcnow.timestamp()) + 7 * 86400,
            constants.SESSION_EXPIRES_AT: int(frozen_datetime.fake_utcnow.timestamp()) + 7 * 86400,
        }

    @patch('oauth2_authcodeflow.auth.AuthenticationBackend.get_or_create_user')
    @patch('oauth2_authcodeflow.auth.AuthenticationBackend.validate_claims')
    @patch('oauth2_authcodeflow.auth.AuthenticationBackend.validate_and_decode_id_token')
    @patch('oauth2_authcodeflow.auth.request_post')
    def test_authenticate_oauth2_return_user_without_pkce_no_secret(
        self, request_post, validate_and_decode_id_token, validate_claims, get_or_create_user,
        frozen_datetime, caplog, db, rf, sf, settings
    ):
        request_post.return_value.status_code = 200
        request_post.return_value.json.return_value = {
            'id_token': 'ID_TOKEN',
            'access_token': 'ACCESS_TOKEN',
        }
        settings.OIDC_RP_CLIENT_ID = 'a_client_id'
        settings.OIDC_RP_CLIENT_SECRET = ''
        settings.OIDC_RP_SCOPES = ['openid', 'email', 'profile']
        settings.OIDC_MIDDLEWARE_SESSION_TIMEOUT_SECONDS = 7 * 86400
        validate_and_decode_id_token.return_value = {
            'aud': settings.OIDC_RP_CLIENT_ID,
            'email': 'my-email@example.com',
        }
        get_or_create_user.return_value = 'user'
        authentication = AuthenticationBackend()
        request = rf.get('/api/protected_resource')
        session = sf(request)
        session[constants.SESSION_OP_TOKEN_URL] = 'token_url'
        session.save()
        request.build_absolute_uri = lambda uri: uri
        assert authentication.authenticate_oauth2(request, False, 'code', 'state', 'nonce', None) == 'user'
        request_post.assert_called_once_with(
            'token_url',
            data={
                'grant_type': 'authorization_code',
                'client_id': settings.OIDC_RP_CLIENT_ID,
                'client_secret': settings.OIDC_RP_CLIENT_SECRET,
                'redirect_uri': '/oidc/callback',
                'code': 'code',
            },
            headers={'origin': '/oidc/callback'},
        )
        assert dict(session.items()) == {
            constants.SESSION_OP_TOKEN_URL: 'token_url',
            constants.SESSION_ID_TOKEN: 'ID_TOKEN',
            constants.SESSION_ACCESS_TOKEN: 'ACCESS_TOKEN',
            constants.SESSION_ACCESS_EXPIRES_AT: int(frozen_datetime.fake_utcnow.timestamp()) + 7 * 86400,
            constants.SESSION_EXPIRES_AT: int(frozen_datetime.fake_utcnow.timestamp()) + 7 * 86400,
        }


class TestBearerAuthenticationBackend:
    JWKS = {'123': {'kid': '123', 'kty': 'RSA', 'alg': 'RS512', 'use': 'sig', 'n': '5wkSa6CQ', 'e': 'AQAB'}},

    @patch('oauth2_authcodeflow.auth.BearerAuthenticationBackend.get_oidc_urls')
    def test_init(self, get_oidc_urls, settings):
        get_oidc_urls.return_value = {constants.SESSION_OP_JWKS: self.JWKS}
        settings.OIDC_AUTHORIZATION_HEADER_PREFIX = 'test'
        authentication = BearerAuthenticationBackend()
        assert isinstance(authentication, OIDCUrlsMixin)
        assert isinstance(authentication, AuthenticationMixin)
        assert isinstance(authentication, ModelBackend)
        get_oidc_urls.assert_called_once_with({})
        assert authentication.authorization_prefix == 'test'
        assert authentication.oidc_urls == {constants.SESSION_OP_JWKS: self.JWKS}

    @patch('oauth2_authcodeflow.auth.BlacklistedToken.is_blacklisted')
    @patch('oauth2_authcodeflow.auth.BearerAuthenticationBackend.get_or_create_user')
    @patch('oauth2_authcodeflow.auth.BearerAuthenticationBackend.validate_and_decode_id_token')
    @patch('oauth2_authcodeflow.auth.BearerAuthenticationBackend.get_oidc_urls')
    def test_authenticate_return_none(self, get_oidc_urls, validate_and_decode_id_token, get_or_create_user, is_blacklisted, caplog, rf, settings):
        get_oidc_urls.return_value = {constants.SESSION_OP_JWKS: self.JWKS}
        validate_and_decode_id_token.return_value = {'email': 'my-email@example.com'}
        get_or_create_user.return_value = 'user'
        is_blacklisted.return_value = True
        settings.OIDC_AUTHORIZATION_HEADER_PREFIX = 'Prefix'
        request = rf.get('/api/protected_resource')
        authentication = BearerAuthenticationBackend()
        assert authentication.authenticate(request) is None
        request = rf.get('/api/protected_resource', HTTP_AUTHORIZATION='Prefix ')
        assert authentication.authenticate(request) is None
        request = rf.get('/api/protected_resource', HTTP_AUTHORIZATION='BadPrefix Token')
        assert authentication.authenticate(request) is None
        request = rf.get('/api/protected_resource', HTTP_AUTHORIZATION='Prefix Token')
        assert authentication.authenticate(request) is None

    @patch('oauth2_authcodeflow.auth.BlacklistedToken.is_blacklisted')
    @patch('oauth2_authcodeflow.auth.BearerAuthenticationBackend.get_or_create_user')
    @patch('oauth2_authcodeflow.auth.BearerAuthenticationBackend.validate_and_decode_id_token')
    @patch('oauth2_authcodeflow.auth.BearerAuthenticationBackend.get_oidc_urls')
    def test_authenticate_return_user(self, get_oidc_urls, validate_and_decode_id_token, get_or_create_user, is_blacklisted, caplog, rf, settings):
        get_oidc_urls.return_value = {constants.SESSION_OP_JWKS: self.JWKS}
        validate_and_decode_id_token.return_value = {'email': 'my-email@example.com'}
        get_or_create_user.return_value = 'user'
        is_blacklisted.return_value = False
        settings.OIDC_AUTHORIZATION_HEADER_PREFIX = 'Prefix'
        request = rf.get('/api/protected_resource', HTTP_AUTHORIZATION='Prefix Token')
        authentication = BearerAuthenticationBackend()
        assert authentication.authenticate(request) == 'user'
        validate_and_decode_id_token.assert_called_once_with('Token', nonce=None, jwks=self.JWKS)
        get_or_create_user.assert_called_once_with(request, {'email': 'my-email@example.com'}, '')
        is_blacklisted.assert_called_once_with('Token')
