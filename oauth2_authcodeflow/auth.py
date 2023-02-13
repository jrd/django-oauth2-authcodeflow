from datetime import (
    datetime,
    timezone,
)
from inspect import signature
from logging import (
    debug,
    warning,
)
from re import search
from typing import (
    Dict,
    Optional,
    Type,
    cast,
)

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import (
    AbstractBaseUser,
    AbstractUser,
)
from django.core.exceptions import SuspiciousOperation
from django.http.request import HttpRequest
from django.urls import reverse
from jose import (
    JWTError,
    jwt,
)
from requests import get as request_get
from requests import post as request_post

from .conf import (
    constants,
    settings,
)
from .models import BlacklistedToken
from .utils import OIDCUrlsMixin


class AuthenticationMixin:
    UserModel: Type[AbstractUser] = cast(Type[AbstractUser], get_user_model())

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
        try:
            claims = jwt.decode(
                id_token,
                key,
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
        except JWTError as e:
            raise SuspiciousOperation("JWT token verification failed: " + str(e))
        if nonce is not None and claims.get('nonce') != nonce:
            raise SuspiciousOperation("JWT Nonce verification failed")
        return claims

    def validate_claims(self, claims: Dict) -> None:
        expected_list = [settings.OIDC_OP_EXPECTED_EMAIL_CLAIM] + list(settings.OIDC_OP_EXPECTED_CLAIMS)
        debug(f"Validate claims={claims} against expected {expected_list}")
        for expected in expected_list:
            if expected not in claims:
                raise SuspiciousOperation(f"'{expected}' claim was expected")

    def get_or_create_user(self, request, id_claims: Dict, access_token: str) -> AbstractUser:
        claims = self.get_full_claims(request, id_claims, access_token)
        username = settings.OIDC_DJANGO_USERNAME_FUNC(claims)
        user, created = self.UserModel.objects.get_or_create(username=username)
        self.update_user(user, created, claims, request, access_token)
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

    def update_user(self, user: AbstractUser, created: bool, claims: Dict, request, access_token: str) -> None:
        """update the django user with data from the claims"""
        if callable(settings.OIDC_EMAIL_CLAIM):
            user.email = settings.OIDC_EMAIL_CLAIM(claims)
        else:
            email_claim_name = settings.OIDC_EMAIL_CLAIM
            if not email_claim_name:
                email_claim_name = settings.OIDC_OP_EXPECTED_EMAIL_CLAIM
            user.email = claims.get(email_claim_name, '')
        if callable(settings.OIDC_FIRSTNAME_CLAIM):
            user.first_name = settings.OIDC_FIRSTNAME_CLAIM(claims)
        else:
            user.first_name = claims.get(settings.OIDC_FIRSTNAME_CLAIM, '')
        if callable(settings.OIDC_LASTNAME_CLAIM):
            user.last_name = settings.OIDC_LASTNAME_CLAIM(claims)
        else:
            user.last_name = claims.get(settings.OIDC_LASTNAME_CLAIM, '')
        if settings.OIDC_UNUSABLE_PASSWORD or created:
            user.set_unusable_password()
        if callable(settings.OIDC_EXTEND_USER):
            extend_user = settings.OIDC_EXTEND_USER
            if len(signature(extend_user).parameters) > 2:
                extend_user(user, claims, request, access_token)
            else:  # backward compatibility
                extend_user(user, claims)
        user.is_active = True


class AuthenticationBackend(ModelBackend, AuthenticationMixin):
    def authenticate(self, request: HttpRequest, username: Optional[str] = None, password: Optional[str] = None, **kwargs) -> Optional[AbstractBaseUser]:
        """Authenticates users using OpenID Connect Authorization code flow."""
        for url_pattern in settings.OIDC_MIDDLEWARE_NO_AUTH_URL_PATTERNS:
            if search(url_pattern, request.path):
                return None
        use_pkce: bool = kwargs.pop('use_pkce', None)
        code: str = kwargs.pop('code', None)
        if use_pkce is None or code is None:
            return None
        state: Optional[str] = kwargs.pop('state', None)
        nonce: Optional[str] = kwargs.pop('nonce', None)
        code_verifier: Optional[str] = kwargs.pop('code_verifier', None)
        return self.authenticate_oauth2(request, use_pkce, code, state, nonce, code_verifier, **kwargs)

    def authenticate_oauth2(self,
                            request: HttpRequest,
                            use_pkce: bool,
                            code: str,
                            state: Optional[str],
                            nonce: Optional[str],
                            code_verifier: Optional[str],
                            **kwargs) -> Optional[AbstractBaseUser]:
        """Authenticates users using OpenID Connect Authorization code flow."""
        if not request:
            return None
        try:
            if use_pkce:
                if not code or not code_verifier:
                    raise SuspiciousOperation('code and code_verifier values are required')
            else:
                if not code or not state or not nonce:
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
            access_expires_in = result.get('expires_in')  # in secs, could be missing
            refresh_token = result.get('refresh_token') if 'offline_access' in settings.OIDC_RP_SCOPES else None
            id_claims = self.validate_and_decode_id_token(id_token, nonce, request.session.get(constants.SESSION_OP_JWKS, {}))
            self.validate_claims(id_claims)
            now_ts = int(datetime.now(tz=timezone.utc).timestamp())
            session_expires_at = now_ts + settings.OIDC_MIDDLEWARE_SESSION_TIMEOUT_SECONDS
            if access_expires_in:
                access_expires_at = now_ts + access_expires_in
            else:
                access_expires_at = id_claims.get('exp', session_expires_at)
            request.session[constants.SESSION_ID_TOKEN] = id_token
            request.session[constants.SESSION_ACCESS_TOKEN] = access_token
            request.session[constants.SESSION_ACCESS_EXPIRES_AT] = access_expires_at
            request.session[constants.SESSION_EXPIRES_AT] = session_expires_at
            if refresh_token:
                request.session[constants.SESSION_REFRESH_TOKEN] = refresh_token
            user = self.get_or_create_user(request, id_claims, access_token)
            return user
        except Exception as e:
            warning(str(e), exc_info=True)
            return None
        finally:
            # be sure the session is in sync
            request.session.save()


class BearerAuthenticationBackend(ModelBackend, AuthenticationMixin, OIDCUrlsMixin):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.authorization_prefix = settings.OIDC_AUTHORIZATION_HEADER_PREFIX
        self.oidc_urls = self.get_oidc_urls({})

    def authenticate(self, request: HttpRequest, username: Optional[str] = None, password: Optional[str] = None, **kwargs) -> Optional[AbstractBaseUser]:
        """Authenticates users using the Authorization header and previous OIDC Id Token."""
        auth_header = request.headers.get('Authorization', '')
        prefix, id_token = auth_header.split(' ', 1) if ' ' in auth_header else ('', '')
        if not prefix or not id_token:
            return None
        try:
            if prefix != self.authorization_prefix:
                raise SuspiciousOperation(f"Authorization should start with a {self.authorization_prefix} prefix")
            if BlacklistedToken.is_blacklisted(id_token):
                raise SuspiciousOperation(f"token {id_token} is blacklisted")
            id_claims = self.validate_and_decode_id_token(id_token, nonce=None, jwks=self.oidc_urls.get(constants.SESSION_OP_JWKS, {}))
            user = self.get_or_create_user(request, id_claims, '')
            return user
        except Exception as e:
            warning(str(e), exc_info=True)
            return None
