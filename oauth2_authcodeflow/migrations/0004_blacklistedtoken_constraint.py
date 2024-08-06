from django.db import (
    migrations,
    models,
)
from django.db.utils import OperationalError


class Migration(migrations.Migration):
    atomic = True
    dependencies = [
        ('oauth2_authcodeflow', '0003_auto_20210528_1432'),
    ]
    operations = [
        migrations.AddConstraint(
            model_name='blacklistedtoken',
            constraint=models.UniqueConstraint(fields=('username', 'token'), name='unique_username_token'),
        ),
    ]

    def apply(self, project_state, *args, **kwargs):
        try:
            super().apply(project_state, *args, **kwargs)
        except OperationalError:
            # Mysql: Specified key was too long; max key length is 3072 bytes
            # => fake the migration
            pass
        return project_state
