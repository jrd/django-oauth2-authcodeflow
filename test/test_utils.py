from contextlib import nullcontext
from unittest.mock import MagicMock
from unittest.mock import patch

import pytest
from django.core.exceptions import ImproperlyConfigured
from django.urls import reverse

from oauth2_authcodeflow import constants
from oauth2_authcodeflow.utils import OIDCUrlsMixin
from oauth2_authcodeflow.utils import login_required


@pytest.mark.parametrize('config', [
    dict(
        OIDC_OP_DISCOVERY_DOCUMENT_URL=None,
        OIDC_OP_AUTHORIZATION_URL=None,
        OIDC_OP_TOKEN_URL=None,
        OIDC_OP_USERINFO_URL=None,
        OIDC_OP_JWKS_URL=None,
        OIDC_OP_END_SESSION_URL=None,
    ),
    dict(
        OIDC_OP_DISCOVERY_DOCUMENT_URL='discovery_url1',
        OIDC_OP_AUTHORIZATION_URL=None,
        OIDC_OP_TOKEN_URL=None,
        OIDC_OP_USERINFO_URL=None,
        OIDC_OP_JWKS_URL=None,
        OIDC_OP_END_SESSION_URL=None,
    ),
    dict(
        OIDC_OP_DISCOVERY_DOCUMENT_URL='discovery_url2',
        OIDC_OP_AUTHORIZATION_URL=None,
        OIDC_OP_TOKEN_URL=None,
        OIDC_OP_USERINFO_URL=None,
        OIDC_OP_JWKS_URL=None,
        OIDC_OP_END_SESSION_URL=None,
        OIDC_OP_FETCH_USER_INFO=False,
    ),
    dict(
        OIDC_OP_DISCOVERY_DOCUMENT_URL=None,
        OIDC_OP_AUTHORIZATION_URL='auth_url',
        OIDC_OP_TOKEN_URL='token_url',
        OIDC_OP_USERINFO_URL='user_url',
        OIDC_OP_JWKS_URL='jwks_url',
        OIDC_OP_END_SESSION_URL='end_session_url',
    ),
], ids=['empty_config', 'with_discovery1', 'with_discovery2', 'without_discovery'])
@pytest.mark.parametrize('session', [
    pytest.param({}, id='empty_session'),
    pytest.param({
        constants.SESSION_OP_AUTHORIZATION_URL: 'auth_url',
        constants.SESSION_OP_TOKEN_URL: 'token_url',
        constants.SESSION_OP_USERINFO_URL: 'user_url',
        constants.SESSION_OP_JWKS_URL: 'jwks_url',
        constants.SESSION_OP_END_SESSION_URL: 'end_session_url',
        constants.SESSION_OP_CLAIMS_PARAMETER_SUPPORTED: True,
        constants.SESSION_OP_JWKS: {'125': {'kid': '125', 'kty': 'RSA', 'use': 'sig', 'value': 3}},
    }, id='full_session'),
])
@patch('oauth2_authcodeflow.utils.settings')
@patch('oauth2_authcodeflow.utils.request_get')
def test_get_oidc_urls(request_get, settings, config, session):
    for key, value in config.items():
        setattr(settings, key, value)
    discovery_response1 = MagicMock(**{'json.return_value': {
        'authorization_endpoint': 'auth_url',
        'token_endpoint': 'token_url',
        'userinfo_endpoint': 'user_url',
        'jwks_uri': 'jwks_url',
        'end_session_endpoint': 'end_session_url',
        constants.OIDC_CLAIMS_PARAMETER_SUPPORTED: True,
    }})
    discovery_response2 = MagicMock(**{'json.return_value': {
        'authorization_endpoint': 'auth_url',
        'token_endpoint': 'token_url',
        'userinfo_endpoint': 'user_url',
    }})
    jwks_response = MagicMock(**{'json.return_value': {
        'keys': [
            {'kid': '123', 'kty': 'TEST', 'use': 'test', 'value': 1},
            {'kid': '124', 'kty': 'RSA', 'use': 'test', 'value': 2},
            {'kid': '125', 'kty': 'RSA', 'use': 'sig', 'value': 3},
            {'kid': '126', 'kty': 'TEST', 'use': 'sig', 'value': 4},
        ],
    }})
    request_get.side_effect = lambda url: {'discovery_url1': discovery_response1, 'discovery_url2': discovery_response2, 'jwks_url': jwks_response}.get(url)
    if not session and not settings.OIDC_OP_DISCOVERY_DOCUMENT_URL and not settings.OIDC_OP_AUTHORIZATION_URL:
        ctx = pytest.raises(ImproperlyConfigured, match="OIDC_OP_AUTHORIZATION_URL is undefined")
    else:
        ctx = nullcontext()
    with ctx:
        new_session = OIDCUrlsMixin().get_oidc_urls(session)
        expected_session = {
            'oidc_op_authorization_url': 'auth_url',
            'oidc_op_token_url': 'token_url',
            'oidc_op_userinfo_url': 'user_url',
            'oidc_op_jwks_url': 'jwks_url',
            'oidc_op_end_session_url': 'end_session_url',
            'oidc_op_claims_parameter_supported': config.get('OIDC_OP_FETCH_USER_INFO', True),
            'oidc_op_jwks': {'125': {'kid': '125', 'kty': 'RSA', 'use': 'sig', 'value': 3}},
        }
        if session:
            expected_session.update({
                'oidc_op_claims_parameter_supported': session.get(constants.SESSION_OP_CLAIMS_PARAMETER_SUPPORTED, False),
            })
        elif not session and settings.OIDC_OP_DISCOVERY_DOCUMENT_URL == 'discovery_url2':
            expected_session.update({
                'oidc_op_jwks_url': None,
                'oidc_op_end_session_url': None,
                'oidc_op_jwks': {},
            })
        assert new_session == expected_session
        if not session:
            if settings.OIDC_OP_DISCOVERY_DOCUMENT_URL == 'discovery_url1':
                assert request_get.call_count == 2
                request_get.assert_any_call(settings.OIDC_OP_DISCOVERY_DOCUMENT_URL)
                discovery_response1.json.assert_called_once()
                discovery_response2.json.assert_not_called()
                request_get.assert_any_call('jwks_url')
                jwks_response.json.assert_called_once()
            elif settings.OIDC_OP_DISCOVERY_DOCUMENT_URL == 'discovery_url2':
                assert request_get.call_count == 1
                request_get.assert_any_call(settings.OIDC_OP_DISCOVERY_DOCUMENT_URL)
                discovery_response1.json.assert_not_called()
                discovery_response2.json.assert_called_once()
                jwks_response.json.assert_not_called()
            else:
                assert request_get.call_count == 1
                request_get.assert_any_call('jwks_url')
                jwks_response.json.assert_called_once()


@patch('oauth2_authcodeflow.utils.orig_login_required')
def test_login_required(orig_login_required, settings):
    orig_login_required.side_effect = lambda func, *args, **kwargs: func
    settings.OIDC_REDIRECT_OK_FIELD_NAME = 'when_ok'
    settings.OIDC_REDIRECT_ERROR_FIELD_NAME = 'when_error'

    def myview(request):
        return 'a test'

    decorated = login_required(myview)
    assert decorated is myview
    orig_login_required.assert_called_once_with(
        myview,
        redirect_field_name='when_ok',
        login_url=reverse(constants.OIDC_URL_AUTHENTICATION_NAME) + '?when_error=%2F',
    )
