from oauth2_authcodeflow import constants
from oauth2_authcodeflow.urls import urlpatterns


def test_urlpatterns():
    def find_url_pattern(name):
        return next(iter(up for up in urlpatterns if up.name == name), None)
    authenticate_url = find_url_pattern(constants.OIDC_URL_AUTHENTICATION_NAME)
    callback_url = find_url_pattern(constants.OIDC_URL_CALLBACK_NAME)
    logout_url = find_url_pattern(constants.OIDC_URL_LOGOUT_NAME)
    total_logout_url = find_url_pattern(constants.OIDC_URL_TOTAL_LOGOUT_NAME)
    logout_by_op_url = find_url_pattern(constants.OIDC_URL_LOGOUT_BY_OP_NAME)
    assert authenticate_url.pattern.regex.pattern == r'^authenticate\Z'
    assert authenticate_url.lookup_str == 'oauth2_authcodeflow.views.AuthenticateView'
    assert callback_url.pattern.regex.pattern == r'^callback\Z'
    assert callback_url.lookup_str == 'oauth2_authcodeflow.views.CallbackView'
    assert logout_url.pattern.regex.pattern == r'^logout\Z'
    assert logout_url.lookup_str == 'oauth2_authcodeflow.views.LogoutView'
    assert total_logout_url.pattern.regex.pattern == r'^total_logout\Z'
    assert total_logout_url.lookup_str == 'oauth2_authcodeflow.views.TotalLogoutView'
    assert logout_by_op_url.pattern.regex.pattern == r'^logout_by_op\Z'
    assert logout_by_op_url.lookup_str == 'oauth2_authcodeflow.views.LogoutByOPView'
