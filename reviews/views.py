from rest_framework import generics, permissions, filters, status
from rest_framework.response import Response
from django_filters.rest_framework import DjangoFilterBackend
from .models import Review
from .serializers import ReviewSerializer
from django.utils import timezone
from datetime import timedelta
from rest_framework.views import APIView

class ReviewCreateAPIView(generics.CreateAPIView):
    queryset = Review.objects.all()
    serializer_class = ReviewSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

class AdminReviewListAPIView(generics.ListAPIView):
    serializer_class = ReviewSerializer
    permission_classes = [permissions.IsAdminUser]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = {
        'rating': ['exact', 'gte', 'lte'],
        'created_at': ['gte', 'lte', 'date'],
        'user__email': ['exact', 'icontains'],
        'user__full_name': ['exact', 'icontains']
    }
    search_fields = ['message', 'user__email', 'user__full_name']
    ordering_fields = ['rating', 'created_at']
    ordering = ['-created_at']

    def get_queryset(self):
        queryset = Review.objects.all().select_related('user')
        
        date_from = self.request.query_params.get('date_from')
        date_to = self.request.query_params.get('date_to')
        
        if date_from:
            queryset = queryset.filter(created_at__gte=date_from)
        if date_to:
            queryset = queryset.filter(created_at__lte=date_to)
            
        return queryset

class UserSearchReviewAPIView(generics.ListAPIView):
    serializer_class = ReviewSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [filters.SearchFilter]
    search_fields = ['message', 'user__full_name']
    
    def get_queryset(self):
        queryset = Review.objects.all()
        
        if not self.request.user.is_staff:
            queryset = queryset.filter(user=self.request.user)
            
        return queryset

class AdminDeleteReviewAPIView(APIView):
    queryset = Review.objects.all()
    serializer_class = ReviewSerializer
    permission_classes = [permissions.IsAdminUser]

    def delete(self, request, id, *args, **kwargs):
        try:
            review = self.queryset.get(id=id)
            review.delete()
            return Response(
                {"message": "Review deleted successfully."},
                status=status.HTTP_204_NO_CONTENT
            )
        except Review.DoesNotExist:
            return Response(
                {"error": "Review not found."},
                status=status.HTTP_404_NOT_FOUND
            )
    #lookup_field = 'id'

class AdminReviewsDeleteallAPIView(generics.DestroyAPIView):
    permission_classes = [permissions.IsAdminUser]
    queryset = Review.objects.all()

    def delete(self, request, *args, **kwargs):
        deleted_count, _ = self.get_queryset().delete()
        return Response(
            {"message": f"Successfully deleted {deleted_count} reviews."},
            status=status.HTTP_204_NO_CONTENT
        )