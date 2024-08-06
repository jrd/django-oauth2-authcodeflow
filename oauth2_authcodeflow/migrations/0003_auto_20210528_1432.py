from django.db import (
    migrations,
    models,
)


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
    ]
