from django.db import migrations, models
from django.db.utils import IntegrityError

def forwards(apps, schema_editor):
    try:
        migrations.AddConstraint(
            model_name='blacklistedtoken',
            constraint=models.UniqueConstraint(fields=('username', 'token'), name='unique_username_token'),
        ),
    except Exception:
        # no constraint on mysql, max key is 3072 bytes which is not enough
        pass

class Migration(migrations.Migration):
    atomic = True
    dependencies = [
        ('oauth2_authcodeflow', '0003_auto_20210528_1432'),
    ]
    operations = [
        migrations.AlterField(
            model_name='blacklistedtoken',
            name='id',
            field=models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID'),
        ),
        migrations.RunPython(forwards),
    ]

    def apply(self, project_state, *args, **kwargs):
        try:
            super().apply(project_state, *args, **kwargs)
        except IntegrityError:
            # unique_username_token already exists and a generated migration has already been applied
            # => fake the migration
            pass
        return project_state
