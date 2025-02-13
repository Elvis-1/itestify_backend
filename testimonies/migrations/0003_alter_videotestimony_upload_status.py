# Generated by Django 5.1.4 on 2025-02-13 08:41

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('testimonies', '0002_videotestimony_scheduled_datetime'),
    ]

    operations = [
        migrations.AlterField(
            model_name='videotestimony',
            name='upload_status',
            field=models.CharField(choices=[('upload_now', 'upload_now'), ('schedule_for_later', 'schedule_for_later'), ('drafts', 'drafts')], max_length=225),
        ),
    ]
