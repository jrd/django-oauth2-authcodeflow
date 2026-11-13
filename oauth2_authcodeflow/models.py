from datetime import UTC
from datetime import datetime
from datetime import timedelta
from logging import getLogger
from typing import Self
from typing import cast

import jwt
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AbstractUser
from django.db import models
from django.db.utils import DatabaseError
from django.utils.functional import cached_property

from .conf import settings

logger = getLogger(__name__)


class BlacklistedToken(models.Model):
    username = models.CharField(max_length=255, editable=False, db_index=True)
    # no max length in RFC6749 but:
    # - https://docs.microsoft.com/en-us/linkedin/shared/authentication/programmatic-refresh-tokens
    # - https://stackoverflow.com/questions/24892496/max-size-for-oauth-token
    # postgres, sqlite, mysql or oracle required
    token = models.CharField(max_length=15000, editable=False)
    expires_at = models.DateTimeField(db_index=True)
    blacklisted_at = models.DateTimeField(editable=False, db_index=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['username', 'token'], name='unique_username_token'),
        ]

    @classmethod
    def blacklist(cls, token: str) -> Self | None:
        claims = jwt.decode(token, options=dict(verify_signature=False))
        username = settings.OIDC_DJANGO_USERNAME_FUNC(claims)
        now = datetime.now(tz=UTC)
        if 'exp' in claims:
            expires_at = datetime.fromtimestamp(claims['exp'], tz=UTC)
        else:
            expires_at = now + timedelta(seconds=settings.OIDC_BLACKLIST_TOKEN_TIMEOUT_SECONDS)
        try:
            return cls.objects.create(username=username, token=token, expires_at=expires_at, blacklisted_at=now)
        except DatabaseError as e:
            logger.warning(str(e))
            return None

    @classmethod
    def is_blacklisted(cls, token: str) -> bool:
        claims = jwt.decode(token, options=dict(verify_signature=False))
        username = settings.OIDC_DJANGO_USERNAME_FUNC(claims)
        return cls.objects.filter(username=username, token=token).count() > 0

    @classmethod
    def purge(cls) -> int:
        now = datetime.now(tz=UTC)
        nb, _ = cls.objects.filter(expires_at__lte=now).delete()
        return nb

    @cached_property
    def user(self) -> AbstractUser | None:
        User = get_user_model()
        try:
            return cast(AbstractUser, User.objects.get(username=self.username))
        except User.DoesNotExist:
            return None

    def __str__(self) -> str:
        return f"Blacklisted token for {self.username}, expire at {str(self.expires_at)}"
