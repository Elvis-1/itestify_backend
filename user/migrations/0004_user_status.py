# Generated by Django 4.2.19 on 2025-04-14 03:44

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0003_alter_user_last_login_otp'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='status',
            field=models.CharField(blank=True, choices=[('deleted', 'deleted')], max_length=255, null=True),
        ),
    ]
