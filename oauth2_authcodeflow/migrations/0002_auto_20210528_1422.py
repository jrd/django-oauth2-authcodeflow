from django.db import (
    migrations,
    models,
)


class Migration(migrations.Migration):
    dependencies = [
        ('oauth2_authcodeflow', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='blacklistedtoken',
            name='id',
            field=models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID'),
        ),
    ]
