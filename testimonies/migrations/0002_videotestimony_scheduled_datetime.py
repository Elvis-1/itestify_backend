# Generated by Django 5.1.4 on 2025-02-10 14:31

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('testimonies', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='videotestimony',
            name='scheduled_datetime',
            field=models.DateTimeField(blank=True, help_text="Datetime for scheduling the upload (used only for 'Schedule for Later' status)", null=True),
        ),
    ]
