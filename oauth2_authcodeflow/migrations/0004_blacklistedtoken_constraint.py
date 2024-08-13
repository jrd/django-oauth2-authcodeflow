from django.db import (
    migrations,
    models,
)
from django.db.utils import OperationalError, ProgrammingError


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
            pass  # => fake the migration
        except ProgrammingError:
            # constraint already exists.
            # That can happen with an update from library version 1.1.0 on an non-empty database.
            pass  # => fake the migration
        return project_state
