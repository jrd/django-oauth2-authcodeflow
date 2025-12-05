from datetime import datetime
from datetime import timedelta
from datetime import timezone

import pytest
from freezegun import freeze_time
from jose import jwt

from oauth2_authcodeflow.models import BlacklistedToken


@pytest.fixture
def frozen_datetime():
    fake_now = datetime(2023, 1, 1, tzinfo=timezone.utc)
    with freeze_time(fake_now) as frozen_datetime:
        yield frozen_datetime


@pytest.fixture
def settings_email_as_username(settings):
    settings.OIDC_DJANGO_USERNAME_FUNC = lambda claims: claims.get('email', '')
    settings.OIDC_BLACKLIST_TOKEN_TIMEOUT_SECONDS = 300


def test_blacklisted_token_model(frozen_datetime):
    d_bl = frozen_datetime()
    d_exp = d_bl + timedelta(minutes=2)
    bl_token = BlacklistedToken(username='any_username', token='auieauie', expires_at=d_exp, blacklisted_at=d_bl)
    assert str(bl_token) == "Blacklisted token for any_username, expire at 2023-01-01 00:02:00"


def test_blacklist_with_exp(db, frozen_datetime, settings_email_as_username):
    exp_date = frozen_datetime() + timedelta(minutes=2)
    token = jwt.encode({'email': 'my-email@example.com', 'exp': exp_date}, '')
    bl_token = BlacklistedToken.blacklist(token)
    assert bl_token
    assert bl_token.id
    assert bl_token.username == 'my-email@example.com'
    assert bl_token.token == token
    assert bl_token.expires_at == exp_date.replace(tzinfo=timezone.utc)
    assert bl_token.blacklisted_at == frozen_datetime().replace(tzinfo=timezone.utc)
    assert BlacklistedToken.blacklist(token) is None


def test_blacklist_without_exp(db, frozen_datetime, settings_email_as_username):
    exp_date = frozen_datetime() + timedelta(seconds=300)
    token = jwt.encode({'email': 'my-email@example.com'}, '')
    bl_token = BlacklistedToken.blacklist(token)
    assert bl_token.id
    assert bl_token.username == 'my-email@example.com'
    assert bl_token.token == token
    assert bl_token.expires_at == exp_date.replace(tzinfo=timezone.utc)
    assert bl_token.blacklisted_at == frozen_datetime().replace(tzinfo=timezone.utc)


def test_is_blacklisted(db, frozen_datetime, settings_email_as_username):
    token = jwt.encode({'email': 'my-email@example.com'}, '')
    assert BlacklistedToken.is_blacklisted(token) is False
    BlacklistedToken.blacklist(token)
    assert BlacklistedToken.is_blacklisted(token) is True


def test_purge(db, frozen_datetime, settings_email_as_username):
    exp_date = frozen_datetime() - timedelta(minutes=5)
    token1 = jwt.encode({'email': 'my-email@example.com'}, '')
    token2 = jwt.encode({'email': 'my-email@example.com', 'exp': exp_date}, '')
    assert BlacklistedToken.purge() == 0
    BlacklistedToken.blacklist(token1)
    assert BlacklistedToken.purge() == 0
    BlacklistedToken.blacklist(token2)
    assert BlacklistedToken.purge() == 1
    assert BlacklistedToken.purge() == 0


def test_user(db, frozen_datetime, django_user_model):
    user_test = django_user_model.objects.create(username='test@example.com')
    d_bl = frozen_datetime()
    d_exp = d_bl + timedelta(minutes=5)
    bl_token1 = BlacklistedToken(username='username@example.com', token='something', expires_at=d_exp, blacklisted_at=d_bl)
    bl_token2 = BlacklistedToken(username='test@example.com', token='other', expires_at=d_exp, blacklisted_at=d_bl)
    assert bl_token1.user is None
    assert isinstance(bl_token2.user, django_user_model)
    assert bl_token2.user == user_test
