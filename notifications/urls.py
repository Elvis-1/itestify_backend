from django.urls import path
from notifications.views import UnreadNotificationsView


urlpatterns = [
    path("get-unread-notifications/", UnreadNotificationsView.as_view(), name=""),
    path("read-notifications/", UnreadNotificationsView.as_view(), name=""),
]
