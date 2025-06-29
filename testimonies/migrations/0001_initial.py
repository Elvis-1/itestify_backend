# Generated by Django 5.1.4 on 2025-05-31 09:39

import django.db.models.deletion
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('contenttypes', '0002_remove_content_type_name'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='TestimonySettings',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('notify_admin', models.BooleanField(default=True)),
            ],
        ),
        migrations.CreateModel(
            name='InspirationalPictures',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('created_at', models.DateTimeField(auto_now_add=True, null=True, verbose_name='Date Created')),
                ('updated_at', models.DateTimeField(auto_now=True, null=True, verbose_name='Date Updated')),
                ('thumbnail', models.ImageField(upload_to='inspirational_picture/')),
                ('status', models.CharField(choices=[('upload_now', 'upload_now'), ('scheduled', 'scheduled'), ('drafts', 'drafts')], max_length=225)),
                ('downloads_count', models.PositiveIntegerField(default=0)),
                ('scheduled_datetime', models.DateTimeField(blank=True, help_text="Datetime for scheduling the upload (used only for 'Schedule for Later' status)", null=True)),
                ('uploaded_by', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Inspirational Picture',
                'verbose_name_plural': 'Inspirational Pictures',
            },
        ),
        migrations.CreateModel(
            name='TextTestimony',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('created_at', models.DateTimeField(auto_now_add=True, null=True, verbose_name='Date Created')),
                ('updated_at', models.DateTimeField(auto_now=True, null=True, verbose_name='Date Updated')),
                ('title', models.CharField(help_text='Enter Title', max_length=255)),
                ('category', models.CharField(choices=[('healing', 'healing'), ('finance', 'finance'), ('breakthrough', 'breakthrough'), ('protection', 'protection'), ('salvation', 'salvation'), ('deliverance', 'deliverance'), ('restoration', 'restoration'), ('spiritual_growth', 'spiritual growth'), ('education', 'education'), ('career', 'career'), ('other', 'other')], db_index=True, max_length=50)),
                ('rejection_reason', models.TextField(blank=True, null=True)),
                ('content', models.TextField()),
                ('status', models.CharField(choices=[('pending', 'pending'), ('approved', 'approved'), ('rejected', 'rejected')], db_index=True, default='pending', max_length=20)),
                ('uploaded_by', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='VideoTestimony',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('created_at', models.DateTimeField(auto_now_add=True, null=True, verbose_name='Date Created')),
                ('updated_at', models.DateTimeField(auto_now=True, null=True, verbose_name='Date Updated')),
                ('title', models.CharField(help_text='Enter Title', max_length=255)),
                ('category', models.CharField(choices=[('healing', 'healing'), ('finance', 'finance'), ('breakthrough', 'breakthrough'), ('protection', 'protection'), ('salvation', 'salvation'), ('deliverance', 'deliverance'), ('restoration', 'restoration'), ('spiritual_growth', 'spiritual growth'), ('education', 'education'), ('career', 'career'), ('other', 'other')], db_index=True, max_length=50)),
                ('rejection_reason', models.TextField(blank=True, null=True)),
                ('source', models.CharField(blank=True, help_text='Video source', max_length=255, null=True)),
                ('upload_status', models.CharField(choices=[('upload_now', 'upload_now'), ('scheduled', 'scheduled'), ('drafts', 'drafts')], max_length=225)),
                ('video_file', models.FileField(blank=True, help_text='Upload video file', null=True, upload_to='videos/')),
                ('thumbnail', models.ImageField(blank=True, help_text='Upload thumbnail image or leave blank for auto-generated', null=True, upload_to='thumbnails/')),
                ('auto_generate_thumbnail', models.BooleanField(default=True, help_text='Auto-generate thumbnail if no upload')),
                ('scheduled_datetime', models.DateTimeField(blank=True, help_text="Datetime for scheduling the upload (used only for 'Schedule for Later' status)", null=True)),
                ('uploaded_by', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='Comment',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('created_at', models.DateTimeField(auto_now_add=True, null=True, verbose_name='Date Created')),
                ('updated_at', models.DateTimeField(auto_now=True, null=True, verbose_name='Date Updated')),
                ('object_id', models.UUIDField()),
                ('text', models.TextField()),
                ('content_type', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='contenttypes.contenttype')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'abstract': False,
                'unique_together': {('content_type', 'object_id', 'user')},
            },
        ),
        migrations.CreateModel(
            name='Like',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('created_at', models.DateTimeField(auto_now_add=True, null=True, verbose_name='Date Created')),
                ('updated_at', models.DateTimeField(auto_now=True, null=True, verbose_name='Date Updated')),
                ('object_id', models.UUIDField()),
                ('content_type', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='contenttypes.contenttype')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'abstract': False,
                'unique_together': {('content_type', 'object_id', 'user')},
            },
        ),
        migrations.CreateModel(
            name='Share',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('created_at', models.DateTimeField(auto_now_add=True, null=True, verbose_name='Date Created')),
                ('updated_at', models.DateTimeField(auto_now=True, null=True, verbose_name='Date Updated')),
                ('object_id', models.UUIDField()),
                ('content_type', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='contenttypes.contenttype')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'abstract': False,
                'unique_together': {('content_type', 'object_id', 'user')},
            },
        ),
    ]
