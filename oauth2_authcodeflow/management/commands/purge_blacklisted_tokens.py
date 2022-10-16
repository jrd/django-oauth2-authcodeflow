from django.core.management.base import BaseCommand

from oauth2_authcodeflow.models import BlacklistedToken


class Command(BaseCommand):
    help = "Purge the blacklisted tokens with passed expiry dates"

    def handle(self, *args, **options):
        nb = BlacklistedToken.purge()
        self.stdout.write(f"{nb} blacklisted tokens purged")
