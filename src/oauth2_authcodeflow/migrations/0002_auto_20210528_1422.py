from django.db import migrations, models


def forwards(apps, schema_editor):
    try:
        migrations.RemoveConstraint(
            model_name='blacklistedtoken',
            name='unique_username_token',
        )
    except Exception:
        # no removal if it’s not there
        pass


class Migration(migrations.Migration):
    dependencies = [
        ('oauth2_authcodeflow', '0001_initial'),
    ]

    operations = [
        migrations.RunPython(forwards),
        migrations.AlterField(
            model_name='blacklistedtoken',
            name='id',
            field=models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID'),
        ),
    ]
