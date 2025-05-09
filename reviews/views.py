from rest_framework import generics, permissions, filters
from django_filters.rest_framework import DjangoFilterBackend
from .models import Review
from .serializers import ReviewSerializer
from django.utils import timezone
from datetime import timedelta

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
        'user__email': ['exact', 'icontains']
    }
    search_fields = ['message', 'user__email']
    ordering_fields = ['rating', 'created_at']
    ordering = ['-created_at']  # Default ordering

    def get_queryset(self):
        queryset = Review.objects.all().select_related('user')
        
        # Custom date range filters
        date_from = self.request.query_params.get('date_from')
        date_to = self.request.query_params.get('date_to')
        
        if date_from:
            queryset = queryset.filter(created_at__gte=date_from)
        if date_to:
            queryset = queryset.filter(created_at__lte=date_to)
            
        return queryset