from django.urls import path
from .views import ReviewCreateAPIView, AdminReviewListAPIView

urlpatterns = [
    path('reviews/', ReviewCreateAPIView.as_view(), name='review-create'),
    path('admin/reviews/', AdminReviewListAPIView.as_view(), name='admin-review-list'),
]