from io import StringIO
from re import escape

import pytest
from django.core.management import CommandError
from django.core.management import call_command


def test_oidc_urls_parser(settings):
    out, err = StringIO(), StringIO()
    opts = dict(stdout=out, stderr=err)
    settings.ALLOWED_HOSTS = ['127.0.0.1', 'toto.example.com']
    with pytest.raises(CommandError, match=escape("the following arguments are required: host")):
        call_command('oidc_urls', **opts)
    opts.update(secure=True)
    with pytest.raises(CommandError, match=escape("the following arguments are required: host")):
        call_command('oidc_urls', **opts)


def test_oidc_urls_bad_urls(settings):
    opts = dict(stdout=StringIO(), stderr=StringIO())
    settings.ALLOWED_HOSTS = ['127.0.0.1', 'toto.example.com']
    settings.ROOT_URLCONF = 'test.no_urls'
    with pytest.raises(CommandError, match=escape("Reverse for 'oidc_callback' not found")):
        call_command('oidc_urls', 'toto.example.com', **opts)


def test_oidc_urls_output(settings):
    out, err = StringIO(), StringIO()
    opts = dict(stdout=out, stderr=err)
    settings.ALLOWED_HOSTS = ['127.0.0.1', 'toto.example.com']
    call_command('oidc_urls', 'toto.example.com', **opts)
    assert out.getvalue() == (
        "redirect_url: http://toto.example.com/oidc/callback\n"
        "logout_url: http://toto.example.com/oidc/logout_by_op\n"
    )
