from django.urls import path
from .views import TextTestimonyApprovalView, TextTestimonyListView, TestimonySettingsView

urlpatterns = [
    path('text-testimonies/', TextTestimonyListView.as_view(), name='text-testimonies'),
    path('text-testimonies/<int:pk>/review/', TextTestimonyApprovalView.as_view(), name='text-testimony-review'),
    path('testimonies/settings/', TestimonySettingsView.as_view(), name='testimony-settings'),
]