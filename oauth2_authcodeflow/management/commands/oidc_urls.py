from django.core.management.base import (
    BaseCommand,
    CommandError,
)
from django.http import HttpRequest
from django.urls import reverse
from django.urls.exceptions import NoReverseMatch

from oauth2_authcodeflow.conf import constants


class Command(BaseCommand):
    help = "Show the OIDC url (redirect url, logout url) that should be configured for the application"

    def add_arguments(self, parser):
        parser.add_argument('host', type=str, help="public host name")
        parser.add_argument('--secure', action='store_true', help="specify that HTTPS will be used as public access")

    def handle(self, *args, **options):
        try:
            request = HttpRequest()
            request.META['HTTP_HOST'] = options['host']
            request._get_scheme = lambda: 'https' if options['secure'] else 'http'
            redirect_url = request.build_absolute_uri(reverse(constants.OIDC_URL_CALLBACK_NAME))
            logout_url = request.build_absolute_uri(reverse(constants.OIDC_URL_LOGOUT_BY_OP_NAME))
            self.stdout.write(f"redirect_url: {redirect_url}")
            self.stdout.write(f"logout_url: {logout_url}")
        except NoReverseMatch as e:
            raise CommandError(str(e))
