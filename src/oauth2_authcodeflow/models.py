from datetime import (
    datetime,
    timedelta,
)
from logging import warning

from django.contrib.auth import get_user_model
from django.db import models
from django.db.utils import DatabaseError
from django.utils.functional import cached_property
from jose import jwt
from pytz import utc

from .conf import settings


class BlacklistedToken(models.Model):
    username = models.CharField(max_length=255, editable=False, db_index=True)
    token = models.TextField(editable=False)
    expires_at = models.DateTimeField(db_index=True)
    blacklisted_at = models.DateTimeField(editable=False, db_index=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=['username', 'token'], name='unique_username_token'),
        ]

    @classmethod
    def blacklist(cls, token: str):
        claims = jwt.get_unverified_claims(token)
        username = settings.OIDC_DJANGO_USERNAME_FUNC(claims)
        now = datetime.now(tz=utc)
        expires_at = datetime.fromtimestamp(claims['exp'], tz=utc) if 'exp' in claims else now + timedelta(settings.OIDC_BLACKLIST_TOKEN_TIMEOUT_SECONDS)
        try:
            return cls.objects.create(username=username, token=token, expires_at=expires_at, blacklisted_at=now)
        except DatabaseError as e:
            warning(str(e))
            return None

    @classmethod
    def is_blacklisted(cls, token: str):
        claims = jwt.get_unverified_claims(token)
        username = settings.OIDC_DJANGO_USERNAME_FUNC(claims)
        return cls.objects.filter(username=username, token=token).count() > 0

    @classmethod
    def purge(cls):
        now = datetime.now(tz=utc)
        nb, _ = cls.objects.filter(expires_at__lte=now).delete()
        return nb

    @cached_property
    def user(self):
        User = get_user_model()
        try:
            return User.objects.get(username=self.username)
        except User.DoesNotExist:
            return None

    def __str__(self):
        return f"Blacklisted token for {self.username}, expire at {str(self.expires_at)}"
