from django.urls import path
from .views import ReviewCreateAPIView, AdminReviewListAPIView, AdminReviewDeleteAPIView, UserReviewSearchAPIView, AdminDeleteAllReviewsAPIView

urlpatterns = [
    path('reviews/', ReviewCreateAPIView.as_view(), name='review-create'),
    path('admin/reviews/', AdminReviewListAPIView.as_view(), name='admin-review-list'),
    path('admin/reviews/<int:id>/', AdminReviewDeleteAPIView.as_view(), name='admin-review-delete'),
    path('reviews/search/', UserReviewSearchAPIView.as_view(), name='user-review-search'),
    path('admin/reviews/delete_all/', AdminDeleteAllReviewsAPIView.as_view(), name='admin-delete-all-reviews'),
]