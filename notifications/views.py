

# import redis
from common.paginations import StandardResultsSetPagination

from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from notifications.models import Notification
from notifications.serializers import NotificationSerializer
from user.models import User
from common.responses import CustomResponse
from common.error import ErrorCode
from django.db.models import Q
from django.utils.dateparse import parse_date
# import asyncio
# from .tasks import delayed_delete
# from django.core.cache import cache


# Create your views here.


class UnreadNotificationsView(APIView):
    permission_classes = [IsAuthenticated]
    serializer_class = NotificationSerializer
    pagination_class = StandardResultsSetPagination

    # Post Selected Notifications as Read
    def post(self, request):
        user = request.user
        selected_notifications = request.data.get("selected_notifications")
        delete_selected = request.query_params.get("delete_selected", None)

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
                if delete_selected == "True":
                    Notification.objects.filter(
                        id__in=selected_notifications).delete()
                    return CustomResponse.success(
                        message="Notification(s) deleted successfully for admin", status_code=200
                    )
                Notification.objects.filter(
                    id__in=selected_notifications, read=False).update(read=True)
                return CustomResponse.success(
                    message="Notification marked as read successfully for admin", status_code=200
                )
            elif user_id.role.name == "User":
                if delete_selected == "True":
                    Notification.objects.filter(
                        id__in=selected_notifications).delete()
                    return CustomResponse.success(
                        message="Notification(s) deleted successfully for user", status_code=200
                    )
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
        from_date = request.query_params.get("from")
        to_date = request.query_params.get("to")
        search = request.query_params.get("search", "").strip()
        read = request.query_params.get("read", "").strip()

        try:
            user_id = User.objects.get(id=user.id)
        except User.DoesNotExist:
            return CustomResponse.error(
                message="User not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )

        notification = Notification.objects.all()
        paginator = self.pagination_class()
        if user_id.role.name == "User":
            if search:
                notification = notification.filter(
                    Q(verb__icontains=search, target=user_id)
                    | Q(message__icontains=search, target=user_id)
                ).order_by("-timestamp")

            if read == "True":
                notification = notification.filter(read=True, target=user_id).order_by(
                    "-timestamp")

            if read == "False":
                notification = notification.filter(read=False, target=user_id).order_by(
                    "-timestamp")

            if from_date:
                parsed_from_date = parse_date(from_date)
                if parsed_from_date:
                    notification = notification.filter(
                        timestamp__date__gte=parsed_from_date, target=user_id
                    )

            if to_date:
                parsed_to_date = parse_date(to_date)
                if parsed_to_date:
                    # Set time to the end of the day for inclusivity
                    notification = notification.filter(
                        timestamp__date__lte=parsed_to_date, target=user_id)

            notification = notification.filter(target=user_id).order_by(
                "-timestamp"
            )
            notification_data = paginator.paginate_queryset(
                notification, request)
            serializer = self.serializer_class(notification_data, many=True)
            return paginator.get_paginated_response(serializer.data)

        elif user_id.role.name == "Admin" or user_id.role.name == "Super Admin":
            if search:
                notification = notification.filter(
                    Q(verb__icontains=search, role="Admin")
                    | Q(message__icontains=search, role="Admin")
                ).order_by("-timestamp")

            if read == "True":
                notification = notification.filter(read=True, role="Admin").order_by(
                    "-timestamp")

            if read == "False":
                notification = notification.filter(read=False, role="Admin").order_by(
                    "-timestamp")

            if from_date:
                parsed_from_date = parse_date(from_date)
                if parsed_from_date:
                    notification = notification.filter(
                        timestamp__date__gte=parsed_from_date, role="Admin"
                    )

            if to_date:
                parsed_to_date = parse_date(to_date)
                if parsed_to_date:
                    # Set time to the end of the day for inclusivity
                    notification = notification.filter(
                        timestamp__date__lte=parsed_to_date, role="Admin")

            notification = notification.filter(role="Admin").order_by(
                "-timestamp"
            )

        notification_data = paginator.paginate_queryset(
            notification, request)
        serializer = self.serializer_class(
            notification_data, many=True)
        return paginator.get_paginated_response(serializer.data)

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
