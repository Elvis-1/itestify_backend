
import json
from django.conf import settings
# import redis
from notifications.consumers import REDIS_PREFIX
from notifications.utils import notify_user_via_websocket
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from notifications.models import Notification
from notifications.serializers import NotificationSerializer
from user.models import User
from common.responses import CustomResponse
from common.error import ErrorCode
# import asyncio
# from .tasks import delayed_delete
# from django.core.cache import cache


# Create your views here.


class UnreadNotificationsView(APIView):
    permission_classes = [IsAuthenticated]
    serializer_class = NotificationSerializer

    # Post Selected Notifications as Read
    def post(self, request):
        user = request.user
        selected_notifications = request.data.get("selected_notifications")
        print(selected_notifications)

        try:
            user_id = User.objects.get(id=user.id)
        except User.DoesNotExist:
            return CustomResponse.error(
                message="User not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )
        try:
            if user_id.role.name == "Admin" or user_id.role.name == "Super Admin":
                Notification.objects.filter(
                    id__in=selected_notifications, read=False).update(read=True)

                return CustomResponse.success(
                    message="Notification marked as read successfully for admin", status_code=200
                )
            elif user_id.role.name == "User":
                Notification.objects.filter(
                    id__in=selected_notifications, read=False).update(read=True)

                return CustomResponse.success(
                    message="Notification marked as read successfully for user", status_code=200
                )
        except Notification.DoesNotExist:
            return CustomResponse.error(
                message="User does not have any Unread Notification",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )

    # Get All Notifications for User and Admin
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
        notification = Notification.objects.all()

        if user_id.role.name == "User":

            notification = notification.filter(target=user_id).order_by(
                "-timestamp"
            )
            serializer = self.serializer_class(notification, many=True)
            return CustomResponse.success(
                message="Notifications retrieved successfully for user",
                data=serializer.data,
                status_code=200,
            )

        elif user_id.role.name == "Admin" or user_id.role.name == "Super Admin":
            notification = notification.filter(role="Admin").order_by(
                "-timestamp"
            )
            serializer = self.serializer_class(notification, many=True)
            return CustomResponse.success(
                message="Notifications retrieved successfully for admin",
                data=serializer.data,
                status_code=200,
            )
        return CustomResponse.error(
            message="Notifications not found",
            status_code=200,
            err_code=ErrorCode.NOT_FOUND,
        )

    # Mark Single Notification as Read for User and Admin
    def put(self, request, id):
        try:
            notification = Notification.objects.get(id=id)
            if notification.read:
                return CustomResponse.success(
                    message="Notification already marked as read",
                    status_code=200,
                )
            notification.read = True
            notification.save()
            return CustomResponse.success(
                message="Notification marked as read successfully for admin",
                status_code=200,
            )

        except Notification.DoesNotExist:
            return CustomResponse.error(
                message="Notification not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )

    # Delete Single Notification for User and Admin
    def delete(self, request, id):
        try:
            if id:
                notification = Notification.objects.get(
                    id=id)
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
