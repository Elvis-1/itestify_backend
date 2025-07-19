from django.urls import path
from notifications.views import GetAllNotificationsView, UnreadNotificationsView


urlpatterns = [
    path("get-unread-notifications/", UnreadNotificationsView.as_view(), name=""),
    path("read-notifications/<id>/", UnreadNotificationsView.as_view(), name=""),
    path("getall-notifications/", GetAllNotificationsView.as_view(), name=""),
]