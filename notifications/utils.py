from typing import Any, Union
from notifications.models import Notification
import redis
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.conf import settings
import logging


logger = logging.getLogger(__name__)

def notify_user_via_ws(
    user_identifier: Union[int, str],
    payload: Any,
    message_type: str,
    prefix: str
) -> bool:
    """
    Notify a user via WebSocket by sending a message to their channel.

    Args:
        user_identifier (Union[int, str]): The identifier of the user (ID or username).
        payload (Any): The data to send in the notification.
        message_type (str): The type of message to send.
        prefix (str): The prefix for the Redis key.

    Returns:
        bool: True if the notification was sent successfully, False otherwise.
    """
    try:
        redis_client = redis.from_url(settings.REDIS_URL)
        channel_name = redis_client.get(f"{prefix}:{user_identifier}")

        if channel_name:
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.send)(
                channel_name.decode("utf-8"),
                {
                    "type": message_type,
                    "notifications": payload
                }
            )
            return True
        else:
            logger.warning(f"No channel found for user {user_identifier}")
            return False
    except Exception as e:
        logger.error(f"Error notifying user {user_identifier}: {e}")
        return False
    finally:
        try:
            redis_client.close()
        except Exception:
            logger.exception("Failed to close Redis client.")


def get_unreadNotification(testimony, message):
    payload = {}
    get_data = []
    notification = Notification.objects.filter(
        target=testimony.uploaded_by, read=False
    ).order_by("-timestamp")
    for data in notification:
        get_data.append(
            {
                "id": str(data.id),
                "verb": data.verb,
                "created_at": str(data.timestamp),
            }
        )
    payload["data"] = get_data
    payload["user_messsge"] = message
    return payload