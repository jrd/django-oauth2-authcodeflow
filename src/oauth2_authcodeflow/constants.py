for key in [
    'oidc_op_authorization_url',
    'oidc_op_token_url',
    'oidc_op_jwks_url',
    'oidc_op_jwks',
    'oidc_op_end_session_url',
    'oidc_next_url',
    'oidc_fail_url',
    'oidc_state',
    'oidc_nonce',
    'oidc_challenge',
    'oidc_id_token',
    'oidc_access_token',
    'oidc_access_expires_at',
    'oidc_refresh_token',
    'oidc_expires_at',
    'oidc_logout_state',
]:
    locals()[('session' + key[len('oidc'):]).upper()] = key
OIDC_URL_AUTHENTICATION_NAME = 'oidc_authentication'
OIDC_URL_CALLBACK_NAME = 'oidc_callback'
OIDC_URL_LOGOUT_NAME = 'oidc_logout'
OIDC_URL_TOTAL_LOGOUT_NAME = 'oidc_total_logout'
OIDC_URL_LOGOUT_BY_OP_NAME = 'oidc_logout_by_op'
OIDC_FROM_CLI_QUERY_STRING = 'from_cli'
