from logging import warning
from time import time
from typing import (
    Dict,
    Optional,
)

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import AbstractBaseUser
from django.core.exceptions import SuspiciousOperation
from django.urls import reverse
from jose import jwt
from requests import get as request_get
from requests import post as request_post

from .conf import (
    constants,
    settings,
)
from .models import BlacklistedToken
from .utils import OIDCUrlsMixin


class AuthenticationMixin:
    def validate_and_decode_id_token(self, id_token: str, nonce: Optional[str], jwks: Dict) -> Dict:
        header = jwt.get_unverified_header(id_token)
        if 'alg' not in header:
            raise SuspiciousOperation("No alg value found in header")
        algo = header['alg']
        if algo not in settings.OIDC_RP_SIGN_ALGOS_ALLOWED:
            raise SuspiciousOperation(f"The token algorithm {algo} is not allowed ({', '.join(settings.OIDC_RP_SIGN_ALGOS_ALLOWED)})")
        if algo.startswith('RS'):
            if settings.OIDC_RP_IDP_SIGN_KEY:
                key = settings.OIDC_RP_IDP_SIGN_KEY
            else:
                key = jwks.get(header.get('kid'))
                if not key or key.get('alg', algo) != algo:
                    raise SuspiciousOperation(f"No key found matching key id {header.get('kid')} and algorithm {algo}")
        elif algo.startswith('HS'):
            key = settings.OIDC_RP_CLIENT_SECRET
        else:
            raise NotImplementedError(f"Algo {algo} cannot be handled by this authentication backend")
        if isinstance(key, dict):
            secret = key
        else:  # RSA public key (bytes)
            secret = key
        try:
            claims = jwt.decode(
                id_token,
                secret,
                algorithms=settings.OIDC_RP_SIGN_ALGOS_ALLOWED,
                audience=settings.OIDC_RP_CLIENT_ID,
                options={
                    'verify_aud': True,
                    'verify_iss': False,
                    'verify_sub': False,
                    'verify_iat': False,
                    'verify_at_hash': False,
                },
            )
        except jwt.JWTError as e:
            raise SuspiciousOperation("JWT token verification failed: " + str(e))
        if nonce is not None and claims.get('nonce') != nonce:
            raise SuspiciousOperation("JWT Nonce verification failed")
        return claims

    def validate_claims(self, claims):
        for expected in [settings.OIDC_OP_EXPECTED_EMAIL_CLAIM] + list(settings.OIDC_OP_EXPECTED_CLAIMS):
            if expected not in claims:
                raise SuspiciousOperation(f"'{expected}' claim was expected")

    def get_or_create_user(self, request, id_claims: Dict, access_token: str) -> AbstractBaseUser:
        claims = self.get_full_claims(request, id_claims, access_token)
        username = settings.OIDC_DJANGO_USERNAME_FUNC(claims)
        user, _ = self.UserModel.objects.get_or_create(username=username)
        self.update_user(user, claims)
        user.set_unusable_password()
        user.save()
        return user

    def get_full_claims(self, request, id_claims: Dict, access_token: str) -> Dict:
        """access_token is not used here, id_claims is enough"""
        if settings.OIDC_OP_FETCH_USER_INFO and constants.SESSION_OP_USERINFO_URL in request.session and access_token:
            claims = id_claims.copy()
            claims.update(request_get(
                request.session[constants.SESSION_OP_USERINFO_URL],
                headers={'Authorization': f'{settings.OIDC_AUTHORIZATION_HEADER_PREFIX} {access_token}'},
            ).json())
            return claims
        else:
            return id_claims

    def update_user(self, user: AbstractBaseUser, claims: Dict) -> None:
        """udate the django user with data from the claims"""
        if settings.OIDC_EMAIL_CLAIM is None:
            user.email = settings.OIDC_OP_EXPECTED_EMAIL_CLAIM
        elif callable(settings.OIDC_EMAIL_CLAIM):
            user.email = settings.OIDC_EMAIL_CLAIM(claims)
        else:
            user.email = claims.get(settings.OIDC_EMAIL_CLAIM, '')
        if callable(settings.OIDC_FIRSTNAME_CLAIM):
            user.first_name = settings.OIDC_FIRSTNAME_CLAIM(claims)
        else:
            user.first_name = claims.get(settings.OIDC_FIRSTNAME_CLAIM, '')
        if callable(settings.OIDC_LASTNAME_CLAIM):
            user.last_name = settings.OIDC_LASTNAME_CLAIM(claims)
        else:
            user.last_name = claims.get(settings.OIDC_LASTNAME_CLAIM, '')
        user.is_active = True


class AuthenticationBackend(ModelBackend, AuthenticationMixin):
    def __init__(self, *args, **kwargs):
        self.UserModel = get_user_model()

    def authenticate(self, request,
                     use_pkce: bool,
                     code: str,
                     state: Optional[str], nonce: Optional[str],
                     code_verifier: Optional[str],
                     **kwargs) -> AbstractBaseUser:
        """Authenticates users using OpenID Connect Authorization code flow."""
        if not request:
            return None
        try:
            if use_pkce:
                if any((
                    not code,
                    not code_verifier,
                )):
                    raise SuspiciousOperation('code and code_verifier values are required')
            else:
                if any((
                    not code,
                    not state,
                    not nonce,
                )):
                    raise SuspiciousOperation('code, state and nonce values are required')
            params = {
                'grant_type': 'authorization_code',
                'client_id': settings.OIDC_RP_CLIENT_ID,
                'client_secret': settings.OIDC_RP_CLIENT_SECRET,
                'redirect_uri': request.build_absolute_uri(reverse(constants.OIDC_URL_CALLBACK_NAME)),
                'code': code,
            }
            if use_pkce:
                params['code_verifier'] = code_verifier
            resp = request_post(request.session[constants.SESSION_OP_TOKEN_URL], data=params)
            if resp.status_code != 200:
                raise SuspiciousOperation(f"{resp.status_code} {resp.text}")
            result = resp.json()
            id_token = result['id_token']
            access_token = result['access_token']
            expires_in = result.get('expires_in')  # in secs, could be missing
            refresh_token = result.get('refresh_token') if 'offline_access' in settings.OIDC_RP_SCOPES else None
            id_claims = self.validate_and_decode_id_token(id_token, nonce, request.session[constants.SESSION_OP_JWKS])
            self.validate_claims(id_claims)
            now = time()
            if expires_in:
                expires_at = now + expires_in
            else:
                expires_at = id_claims.get('exp', now + settings.OIDC_MIDDLEWARE_SESSION_TIMEOUT_SECONDS)
            request.session[constants.SESSION_ID_TOKEN] = id_token
            request.session[constants.SESSION_ACCESS_TOKEN] = access_token
            request.session[constants.SESSION_ACCESS_EXPIRES_AT] = expires_at
            request.session[constants.SESSION_EXPIRES_AT] = now + settings.OIDC_MIDDLEWARE_SESSION_TIMEOUT_SECONDS
            if refresh_token:
                request.session[constants.SESSION_REFRESH_TOKEN] = refresh_token
            user = self.get_or_create_user(request, id_claims, access_token)
            return user
        except Exception as e:
            warning(e, str(e))
            return None
        finally:
            # be sure the session is in sync
            request.session.save()


class BearerAuthenticationBackend(ModelBackend, AuthenticationMixin, OIDCUrlsMixin):
    def __init__(self, *args, **kwargs):
        self.UserModel = get_user_model()
        self.authorization_prefix = settings.OIDC_AUTHORIZATION_HEADER_PREFIX
        self.oidc_urls = self.get_oidc_urls({})

    def authenticate(self, request, **kwargs) -> AbstractBaseUser:
        """Authenticates users using the Authorization header and previous OIDC Id Token."""
        try:
            prefix, id_token = request.headers.get('Authorization', ' ').split(' ', 1)
        except ValueError:
            prefix = id_token = ''
        if not prefix or not id_token:
            return None
        try:
            if prefix != self.authorization_prefix:
                raise SuspiciousOperation(f"Authorization should start with a {self.authorization_prefix} prefix")
            if BlacklistedToken.is_blacklisted(id_token):
                raise SuspiciousOperation(f"token {id_token} is blacklisted")
            id_claims = self.validate_and_decode_id_token(id_token, nonce=None, jwks=self.oidc_urls.get(constants.SESSION_OP_JWKS, []))
            user = self.get_or_create_user(request, id_claims, None)
            return user
        except Exception as e:
            warning(e.args[0])
            return None
