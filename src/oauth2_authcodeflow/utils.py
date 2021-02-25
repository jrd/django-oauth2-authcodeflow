from typing import Dict

from django.core.exceptions import ImproperlyConfigured
from requests import get as request_get

from .conf import (
    constants,
    settings,
)


class OIDCUrlsMixin:
    def get_oidc_urls(self, session: Dict[str, str]) -> Dict[str, str]:
        session = dict(session.items())  # .copy() is not available on SessionStore
        if settings.OIDC_OP_DISCOVERY_DOCUMENT_URL:
            if any((
                constants.SESSION_OP_AUTHORIZATION_URL not in session,
                constants.SESSION_OP_TOKEN_URL not in session,
                constants.SESSION_OP_USERINFO_URL not in session,
                constants.SESSION_OP_JWKS_URL not in session,
                constants.SESSION_OP_END_SESSION_URL not in session,
            )):
                doc_resp = request_get(settings.OIDC_OP_DISCOVERY_DOCUMENT_URL)
                doc_resp.raise_for_status()
                doc = doc_resp.json()
                session[constants.SESSION_OP_AUTHORIZATION_URL] = doc.get('authorization_endpoint')
                session[constants.SESSION_OP_TOKEN_URL] = doc.get('token_endpoint')
                session[constants.SESSION_OP_USERINFO_URL] = doc.get('userinfo_endpoint')
                session[constants.SESSION_OP_JWKS_URL] = doc.get('jwks_uri')
                session[constants.SESSION_OP_END_SESSION_URL] = doc.get('end_session_endpoint')
        elif any((
            settings.OIDC_OP_AUTHORIZATION_URL,
            settings.OIDC_OP_TOKEN_URL,
            settings.OIDC_OP_USERINFO_URL,
            settings.OIDC_OP_JWKS_URL,
            settings.OIDC_OP_END_SESSION_URL,
        )):
            for conf in ('OP_AUTHORIZATION_URL', 'OP_TOKEN_URL', 'OP_USERINFO_URL', 'OP_JWKS_URL', 'OP_END_SESSION_URL'):
                session_conf = getattr(constants, 'SESSION_' + conf)
                if session_conf not in session:
                    session[session_conf] = getattr(settings, 'OIDC_' + conf)
        for conf in ('OP_AUTHORIZATION_URL', 'OP_TOKEN_URL'):#, 'OP_USERINFO_URL'
            session_conf = getattr(constants, 'SESSION_' + conf)
            if not session.get(session_conf):
                raise ImproperlyConfigured(f'OIDC_{conf} is undefined')
        if session.get(constants.SESSION_OP_JWKS_URL):
            jwks_resp = request_get(session[constants.SESSION_OP_JWKS_URL])
            jwks_resp.raise_for_status()
            jwks = jwks_resp.json()['keys']
        else:
            jwks = []
        session[constants.SESSION_OP_JWKS] = {key['kid']: key for key in jwks if key['kty'] == 'RSA' and key['use'] == 'sig'}
        return session
