import json
from django.conf import settings
from django.shortcuts import render
from notifications.consumers import REDIS_PREFIX
import redis
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from notifications.models import Notification
from notifications.serializers import NotificationSerializer
from user.models import User
from common.responses import CustomResponse
from common.error import ErrorCode
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync

# Create your views here.


class UnreadNotificationsView(APIView):
    permission_classes = [IsAuthenticated]
    serializer_class = NotificationSerializer

    def post(self, request):
        user = request.user
        try:
            user_id = User.objects.get(id=user.id)
        except User.DoesNotExist:
            return CustomResponse.error(
                message="User not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )
        try:
            notification = Notification.objects.filter(target=user_id, read=False).order_by(
                "-timestamp"
            )
            for notif in notification:
                if not notif.read:
                    notif.read = True
                    notif.save()
            payload = {
                "count": str(notification.count()),
            }

            # Notify user via WebSocket
            redis_client = redis.from_url(settings.REDIS_URL)
            # Get user's WebSocket channel from Redis
            channel_name = redis_client.get(
                f"{REDIS_PREFIX}:{str(user_id.id)}")
            if channel_name:
                channel_layer = get_channel_layer()
                async_to_sync(channel_layer.send)(
                    channel_name.decode("utf-8"),
                    {
                        "type": "get_user_unread_notification_count",
                        "notifications": (payload)
                    }
                )
            redis_client.close()
            return CustomResponse.success(
                message="Notification marked as read successfully", status_code=200
            )
        except Notification.DoesNotExist:
            return CustomResponse.error(
                message="User does not have any Unread Notification",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )

    def get(self, request):
        user = request.user
        try:
            user_id = User.objects.get(id=user.id)
        except User.DoesNotExist:
            return CustomResponse.error(
                message="User not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )
        notification = Notification.objects.filter(target=user_id, read=False).order_by(
            "-timestamp"
        )
        if not notification:
            return CustomResponse.error(
                message="No notifications found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )
        serializer = self.serializer_class(notification, many=True)

        return CustomResponse.success(
            message="Notifications retrieved successfully",
            data=serializer.data,
            status_code=200,
        )


class GetAllNotificationsView(APIView):
    permission_classes = [IsAuthenticated]
    serializer_class = NotificationSerializer

    def get(self, request):
        user = request.user
        try:
            user_id = User.objects.get(id=user.id)
        except User.DoesNotExist:
            return CustomResponse.error(
                message="User not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )
        notifications = Notification.objects.filter(target=user_id).order_by(
            "-timestamp"
        )
        if not notifications:
            return CustomResponse.error(
                message="No notifications found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )
        serializer = self.serializer_class(notifications, many=True)

        return CustomResponse.success(
            message="Notifications retrieved successfully",
            data=serializer.data,
            status_code=200,
        )
