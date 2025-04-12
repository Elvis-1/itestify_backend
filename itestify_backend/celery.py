import os

from celery import Celery

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'itestify_backend.settings')

app = Celery('itestify_backend', backend="redis://localhost:6379/0", broker="amqp://guest:guest@localhost:5672//")

app.config_from_object('django.conf:settings', namespace='CELERY')

# Load task modules from all registered Django apps.
app.autodiscover_tasks()
