from rest_framework.views import APIView
from rest_framework import viewsets
from rest_framework import status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.pagination import PageNumberPagination
from rest_framework import status

from support import http
from support.helpers import StandardResultsSetPagination
from .models import TextTestimony, VideoTestimony
from .serializers import ReturnTextTestimonySerializer, ReturnVideoTestimonySerializer, TextTestimonySerializer, VideoTestimonySerializer

class TextTestimonyListView(APIView):
    """Fetch all testimonies with filtering and search."""

    def get(self, request):
        testimonies = TextTestimony.objects.all()
        # Filters
        category = request.query_params.get('category')
        status_filter = request.query_params.get('status')
        search = request.query_params.get('search')
        start_date = request.query_params.get('start_date')
        end_date = request.query_params.get('end_date')

        if category:
            testimonies = testimonies.filter(category=category)
        if status_filter:
            testimonies = testimonies.filter(status=status_filter)
        if search:
            testimonies = testimonies.filter(name__icontains=search)
        if start_date and end_date:
            testimonies = testimonies.filter(date_submitted__range=[start_date, end_date])

        # Pagination
        paginator = PageNumberPagination()
        paginator.page_size = 10
        paginated_testimonies = paginator.paginate_queryset(testimonies, request)

        # Serialize and return
        serializer = TextTestimonySerializer(paginated_testimonies, many=True)
        return paginator.get_paginated_response(serializer.data)


class TextTestimonyApprovalView(APIView):
    """Approve or reject testimonies."""

    def post(self, request, pk):
        try:
            testimony = TextTestimony.objects.get(pk=pk)
        except TextTestimony.DoesNotExist:
            return Response({"error": "Testimony not found"}, status=status.HTTP_404_NOT_FOUND)

        action = request.data.get('action')  # 'approve' or 'reject'
        rejection_reason = request.data.get('rejection_reason', '')

        if action == 'approve':
            testimony.status = 'Approved'
            testimony.rejection_reason = ''
        elif action == 'reject':
            testimony.status = 'Rejected'
            testimony.rejection_reason = rejection_reason
        else:
            return Response({"error": "Invalid action"}, status=status.HTTP_400_BAD_REQUEST)

        testimony.save()
        return Response({"message": "Testimony updated successfully"})


class TestimonySettingsView(APIView):
    """Manage global settings."""

    def get(self, request):
        settings = {
            "likes_enabled": True,
            "comments_enabled": True,
            "shares_enabled": True
        }
        return Response(settings)

    def post(self, request):
        # Update settings logic here
        return Response({"message": "Settings updated successfully"})
    


class TestimonyViewSet(viewsets.ViewSet):
    
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = StandardResultsSetPagination
    
    def list(self, request):
        """Get all testimonies"""
        
        # Get type parameter
        test_type = request.query_params.get("type", "").lower()
        
        
         # Define a mapping for testimony types
        testimony_map = {
            "text": (TextTestimony.objects.all(), ReturnTextTestimonySerializer),
            "video": (VideoTestimony.objects.all(), ReturnVideoTestimonySerializer),
        }
        
        if test_type not in testimony_map:
            return http.failed_response(
                message="Invalid or missing testimony type. Valid types are 'text' or 'video'.",
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        
        # Get the queryset and serializer dynamically
        queryset, serializer_class = testimony_map[test_type]
        
        paginator = self.pagination_class()
        paginated_queryset = paginator.paginate_queryset(queryset, request)
        serializer = serializer_class(paginated_queryset, many=True)
        
        return paginator.get_paginated_response(serializer.data)
    
    @action(detail=False, methods=['post'])
    def create_text(self, request):
        
        serializer = TextTestimonySerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        testimony = serializer.save()
        
        return_serializer = ReturnTextTestimonySerializer(testimony)
        return http.success_response(data=return_serializer.data, status_code=status.HTTP_201_CREATED)
    
    @action(detail=False, methods=['post'])
    def create_video(self, request):
        
        serializer = VideoTestimonySerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        testimony = serializer.save()
        
        return_serializer = ReturnVideoTestimonySerializer(testimony)
        return http.success_response(data=return_serializer.data, status_code=status.HTTP_201_CREATED)
    
    def retrieve(self, request):
        pass
        
        
        
        