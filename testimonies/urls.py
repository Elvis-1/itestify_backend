from django.urls import include, path
from .views import InspirationalPicturesViewSet, TextTestimonyApprovalView, TextTestimonyListView, TestimonySettingsView, TextTestimonyViewSet, VideoTestimonyViewSet
from rest_framework.routers import DefaultRouter


router = DefaultRouter()
router.register(r'testimonies/texts', TextTestimonyViewSet, basename="text-testimonies")
router.register(r'testimonies/videos', VideoTestimonyViewSet, basename="video-testimonies")
router.register(r'inspirational', InspirationalPicturesViewSet, basename="inspirational")

urlpatterns = [
    path('', include(router.urls)),
    path('text-testimonies/', TextTestimonyListView.as_view(), name='text-testimonies'),
    path('text-testimonies/<int:pk>/review/', TextTestimonyApprovalView.as_view(), name='text-testimony-review'),
    path('testimonies/settings/', TestimonySettingsView.as_view(), name='testimony-settings'),
]