# Generated by Django 5.1.4 on 2025-07-17 13:40

import django.contrib.postgres.fields
import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Role',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('created_at', models.DateTimeField(auto_now_add=True, null=True, verbose_name='Date Created')),
                ('updated_at', models.DateTimeField(auto_now=True, null=True, verbose_name='Date Updated')),
                ('name', models.CharField(max_length=255)),
                ('permissions', django.contrib.postgres.fields.ArrayField(base_field=models.CharField(max_length=255), size=None)),
            ],
            options={
                'abstract': False,
            },
        ),
    ]
