from django.db import migrations, models


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

    dependencies = [
        ('oauth2_authcodeflow', '0002_auto_20210528_1422'),
    ]

    operations = [
        migrations.AlterField(
            model_name='blacklistedtoken',
            name='token',
            field=models.CharField(editable=False, max_length=15000),
        ),
        migrations.RunPython(forwards),
    ]
