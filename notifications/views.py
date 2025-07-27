from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from notifications.models import Notification
from notifications.serializers import NotificationSerializer
from user.models import User
from common.responses import CustomResponse
from common.error import ErrorCode

# Create your views here.


class UnreadNotificationsView(APIView):
    permission_classes = [IsAuthenticated]
    serializer_class = NotificationSerializer

    def post(self, request, id):
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
            notification = Notification.objects.get(id=id, target=user_id)
            notification.read = True
            notification.save()
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