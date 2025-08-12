import logging
from notifications.models import Notification
from django.core.cache import cache
from celery import shared_task
import time

logger = logging.getLogger(__name__)
DELETE_DELAY = 5

@shared_task
def delayed_delete(id, user_id):
    time.sleep(DELETE_DELAY)

    key = f"delete:{id}"
    #redis_client = redis.from_url(settings.REDIS_URL)

    if cache.get(key):
        try:
            notification = Notification.objects.get(id=id, target = user_id)
            notification.delete()
            
            logger.info(f"Notification {id} deleted successfully after waited.")
        except Notification.DoesNotExist:
            logger.warning(f"Notification {id} does not exist.")
        cache.delete(key)
    else:
        logger.info(f"Notification {id} was already undo.")