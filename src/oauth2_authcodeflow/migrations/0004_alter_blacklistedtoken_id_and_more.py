from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('oauth2_authcodeflow', '0003_auto_20210528_1432'),
    ]

    operations = [
        migrations.AlterField(
            model_name='blacklistedtoken',
            name='id',
            field=models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID'),
        ),
        migrations.AddConstraint(
            model_name='blacklistedtoken',
            constraint=models.UniqueConstraint(fields=('username', 'token'), name='unique_username_token'),
        ),
    ]
