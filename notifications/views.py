
from notifications.consumers import REDIS_PREFIX
from notifications.utils import notify_user_via_ws
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from notifications.models import Notification
from notifications.serializers import NotificationSerializer
from user.models import User
from common.responses import CustomResponse
from common.error import ErrorCode
import asyncio
from .utils import delayed_delete


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
            updated = Notification.objects.filter(
                target=user_id, read=False).update(read=True)
            payload = {"count": str(updated)}

            notify_user_via_ws(
                user_identifier=user_id.id,
                payload=payload,
                message_type="get_user_unread_notification_count",
                prefix=REDIS_PREFIX
            )
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

        notification = notification.filter(target=user_id).order_by(
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

    def delete(self, request, pk):
        user = request.user
        undo = request.query_params.get("undo")
        try:
            user_id = User.objects.get(id=user.id)
        except User.DoesNotExist:
            return CustomResponse.error(
                message="User not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )

        key = f"delete:{pk}"
        redis_client = redis.get_url(setting.REDIS_URL)
        try:
            if redis_client.get(key):
                if undo == "undo":
                    redis_client.delete(key)
                    return CustomResponse.success(
                        message="Deletion undone successfully",
                        status_code=200,
                    )
            notification = Notification.objects.get(id = pk, target = user_id)
            redis_client.set(key, json.dumps({"id": f"{notification.id}", "user": user_id}))

            asyncio.create_task(delayed_delete(pk, user))

            return CustomResponse.success(
                message="Notification to be deleted in 5sec Successfully",
                status_code=200,
            )
        except Notification.DoesNotExist:
            return CustomResponse.error(
                message="Notification not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )
