from django.urls import path
from .views import ReviewCreateAPIView, AdminReviewListAPIView, AdminDeleteReviewAPIView, UserSearchReviewAPIView, AdminReviewsDeleteallAPIView

urlpatterns = [
    path('reviews/', ReviewCreateAPIView.as_view(), name='review-create'),
    path('admin/reviews/', AdminReviewListAPIView.as_view(), name='admin-review-list'),
    path('admin/reviews/<str:id>/', AdminDeleteReviewAPIView.as_view(), name='admin-review-delete'),
    path('reviews/search/', UserSearchReviewAPIView.as_view(), name='user-review-search'),
    path('admin/reviews/delete_all/', AdminReviewsDeleteallAPIView.as_view(), name='admin-delete-all-reviews'),
]