
import json
from django.conf import settings
#import redis
from notifications.consumers import REDIS_PREFIX
from notifications.utils import notify_user_via_websocket
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from notifications.models import Notification
from notifications.serializers import NotificationSerializer
from user.models import User
from common.responses import CustomResponse
from common.error import ErrorCode
#import asyncio
#from .tasks import delayed_delete
#from django.core.cache import cache


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
            if user_id.role.name == "admin":
                updated = Notification.objects.filter(
                    target=user_id, read=False).update(read=True)
                payload = {"count": str(updated)}

                notify_user_via_websocket(
                    user_identifier=user_id.id,
                    payload=payload,
                    message_type="get_user_unread_notification_count",
                    prefix=REDIS_PREFIX
                )
                return CustomResponse.success(
                    message="Notification marked as read successfully for admin", status_code=200
                )
            elif user_id.role.name == "user":
                updated = Notification.objects.filter(
                    target=user_id, read=False).update(read=True)
                payload = {"count": str(updated)}

                notify_user_via_websocket(
                    user_identifier=user_id.id,
                    payload=payload,
                    message_type="get_user_unread_notification_count",
                    prefix=REDIS_PREFIX
                )
                return CustomResponse.success(
                    message="Notification marked as read successfully for user", status_code=200
                )
        except Notification.DoesNotExist:
            return CustomResponse.error(
                message="User does not have any Unread Notification",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )

    def get(self, request):
        user = request.user
        read = request.query_params.get("read")
        try:
            user_id = User.objects.get(id=user.id)
        except User.DoesNotExist:
            return CustomResponse.error(
                message="User not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )
        notification = Notification.objects.all().order_by("-timestamp")
        if user_id.role.name == "admin":
            serializer = self.serializer_class(notification, many=True)
            return CustomResponse.success(
                message="Notifications retrieved successfully for admin",
                data=serializer.data,
                status_code=200,
            )

        elif user_id.role.name == "user":
            if read == "False":
                notification = notification.filter(target=user_id, read=False).order_by(
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
                    message="Notifications retrieved successfully for user",
                    data=serializer.data,
                    status_code=200,
                )
            notification = notification.filter(target=user_id, read=True).order_by(
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
                message="Notifications retrieved successfully for user",
                data=serializer.data,
                status_code=200,
            )

    def put(self, request, id):
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
            if user_id.role.name == "admin":
                notification = Notification.objects.get(id=id, target=user_id)
                notification.read = True
                notification.save()
                # payload = {"count": "1"}

                '''notify_user_via_ws(
                    user_identifier=user_id.id,
                    payload=payload,
                    message_type="get_user_unread_notification_count",
                    prefix=REDIS_PREFIX
                )'''
                return CustomResponse.success(
                    message="Notification marked as read successfully for admin",
                    status_code=200,
                )
            elif user_id.role.name == "user":
                notification = Notification.objects.get(id=id, target=user_id)
                notification.read = True
                notification.save()
                # payload = {"count": "1"}

                '''notify_user_via_ws(
                    user_identifier=user_id.id,
                    payload=payload,
                    message_type="get_user_unread_notification_count",
                    prefix=REDIS_PREFIX
                )'''
                return CustomResponse.success(
                    message="Notification marked as read successfully for user",
                    status_code=200,
                )
        except Notification.DoesNotExist:
            return CustomResponse.error(
                message="Notification not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )

    def delete(self, request, id=None):
        user = request.user
        read = request.query_params.get("read", None)
        try:
            user_id = User.objects.get(id=user.id)
        except User.DoesNotExist:
            return CustomResponse.error(
                message="User not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )
        try:
            if user_id.role.name == "admin":
                if id:
                    notification = Notification.objects.get(id=id, target=user_id)
                    notification.delete()
                    return CustomResponse.success(
                        message="Notification deleted Successfully by admin",
                        status_code=200,
                    )
                else:
                    Notification.objects.filter(target=user_id, read = read).delete()
                    return CustomResponse.success(
                        message="All notifications deleted Successfully by admin",
                        status_code=200,
                    )
            elif user_id.role.name == "user":
                if id:
                    notification = Notification.objects.get(id=id, target=user_id)
                    notification.delete()
                    return CustomResponse.success(
                        message="Notification deleted Successfully",
                        status_code=200,
                    )

        except Notification.DoesNotExist:
            return CustomResponse.error(
                message="Notification not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )
