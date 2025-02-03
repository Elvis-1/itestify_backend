from django.urls import path
from .views import TextTestimonyApprovalView, TextTestimonyListView, TestimonySettingsView
from rest_framework.routers import DefaultRouter
from .views import TestimonyViewSet


router = DefaultRouter()
router.register(r'testimonies', TestimonyViewSet, basename="testimonies")

urlpatterns = [
    path('text-testimonies/', TextTestimonyListView.as_view(), name='text-testimonies'),
    path('text-testimonies/<int:pk>/review/', TextTestimonyApprovalView.as_view(), name='text-testimony-review'),
    path('testimonies/settings/', TestimonySettingsView.as_view(), name='testimony-settings'),
] + router.urls