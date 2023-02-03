from io import StringIO
from unittest.mock import patch

from django.core.management import call_command


@patch('oauth2_authcodeflow.management.commands.purge_blacklisted_tokens.BlacklistedToken')
def test_purge_blacklisted_tokens(BlacklistedToken):
    BlacklistedToken.purge.return_value = 2
    out, err = StringIO(), StringIO()
    opts = dict(stdout=out, stderr=err)
    call_command('purge_blacklisted_tokens', **opts)
    assert out.getvalue() == "2 blacklisted tokens purged\n"
    BlacklistedToken.purge.assert_called_once_with()
    BlacklistedToken.purge.reset_mock()
    BlacklistedToken.purge.return_value = 0
    out, err = StringIO(), StringIO()
    opts = dict(stdout=out, stderr=err)
    call_command('purge_blacklisted_tokens', **opts)
    assert out.getvalue() == "0 blacklisted tokens purged\n"
    BlacklistedToken.purge.assert_called_once_with()
