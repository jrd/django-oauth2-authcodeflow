from django.db import (
    migrations,
    models,
)
from django.db.utils import IntegrityError


class Migration(migrations.Migration):
    atomic = True
    dependencies = [
        ('oauth2_authcodeflow', '0004_blacklistedtoken_constraint'),
    ]
    operations = [
        migrations.AlterField(
            model_name='blacklistedtoken',
            name='id',
            field=models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID'),
        ),
    ]

    def apply(self, project_state, *args, **kwargs):
        try:
            super().apply(project_state, *args, **kwargs)
        except IntegrityError:
            # unique_username_token already exists and a generated migration has already been applied
            # => fake the migration
            pass
        return project_state
