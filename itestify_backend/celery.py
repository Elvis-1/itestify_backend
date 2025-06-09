import os

from celery import Celery

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'itestify_backend.settings')

app = Celery('itestify_backend', backend="redis://localhost:6379/0", broker="redis-11510.c73.us-east-1-2.ec2.redns.redis-cloud.com:11510")

app.config_from_object('django.conf:settings', namespace='CELERY')

# Load task modules from all registered Django apps.
app.autodiscover_tasks()
