from django.urls import path

from .views import MediaUploadViewAPIView, health_check


urlpatterns = [
    path("health", health_check, name="health"),
    path("upload", MediaUploadViewAPIView.as_view(), name="upload"),
]