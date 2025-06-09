from django.urls import path

from .views import MediaUploadViewAPIView


urlpatterns = [
    path("upload", MediaUploadViewAPIView.as_view(), name="upload"),
]