# Generated manually to create fresh donation tables

import django.core.validators
import django.db.models.deletion
import uuid
from decimal import Decimal
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('donations', '0001_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        # Drop existing tables if they exist
        migrations.RunSQL(
            "DROP TABLE IF EXISTS donations_gift CASCADE;",
            reverse_sql="",
        ),
        migrations.RunSQL(
            "DROP TABLE IF EXISTS donations_donation CASCADE;",
            reverse_sql="",
        ),
        
        # Recreate Donation table with correct structure
        migrations.CreateModel(
            name='Donation',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('created_at', models.DateTimeField(auto_now_add=True, null=True, verbose_name='Date Created')),
                ('updated_at', models.DateTimeField(auto_now=True, null=True, verbose_name='Date Updated')),
                ('full_name', models.CharField(blank=True, max_length=255, null=True)),
                ('email', models.EmailField(blank=True, max_length=255, null=True)),
                ('reference', models.CharField(blank=True, help_text='Unique transaction reference', max_length=100, null=True, unique=True)),
                ('amount', models.DecimalField(decimal_places=2, help_text='Transaction amount', max_digits=12, validators=[django.core.validators.MinValueValidator(Decimal('0.01'))])),
                ('transaction_type', models.CharField(choices=[('BANK', 'BANK'), ('TRANSFER', 'TRANSFER'), ('CARD', 'CARD')], max_length=10)),
                ('currency', models.CharField(choices=[('NGN', 'NGN'), ('USD', 'USD')], max_length=3)),
                ('session_id', models.CharField(blank=True, max_length=255, null=True)),
                ('status', models.CharField(choices=[('PENDING', 'Pending'), ('SUCCESS', 'Success'), ('FAILED', 'Failed'), ('CANCELLED', 'Cancelled')], default='PENDING', max_length=20)),
                ('description', models.TextField(blank=True, null=True)),
                ('metadata', models.JSONField(blank=True, default=dict)),
                ('tx_ref', models.CharField(blank=True, max_length=128, null=True, unique=True)),
                ('user', models.ForeignKey(blank=True, help_text='User who initiated the transaction', null=True, on_delete=django.db.models.deletion.CASCADE, related_name='donations', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'verbose_name': 'Transaction History',
                'verbose_name_plural': 'Transaction Histories',
                'ordering': ['-created_at'],
                'indexes': [
                    models.Index(fields=['user'], name='donations_d_user_id_d6646f_idx'),
                    models.Index(fields=['status'], name='donations_d_status_73ca83_idx'),
                    models.Index(fields=['tx_ref'], name='donations_d_tx_ref_7328ed_idx'),
                ],
            },
        ),
    ]