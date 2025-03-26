from django.urls import path
from .views import TextTestimonyViewSet, TextTestimonyListView, VideoTestimonyViewSet
from rest_framework.routers import DefaultRouter



router = DefaultRouter()
router.register(r"testimonies/texts", TextTestimonyViewSet, basename="text-testimonies")
router.register(r"testimonies/videos", VideoTestimonyViewSet, basename="video-testimonies")



urlpatterns = [
    path("text_testimonies/", TextTestimonyListView.as_view(), name="text-testimonies"),
] + router.urls
