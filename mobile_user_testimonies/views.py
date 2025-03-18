from common.responses import CustomResponse
from common.paginations import StandardResultsSetPagination
from common.error import ErrorCode
from common.exceptions import handle_custom_exceptions
from .serializers import TextTestimonySerializer
from testimonies.models import TextTestimony, VideoTestimony
from rest_framework.generics import GenericAPIView
from rest_framework import viewsets, permissions
from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import action
from .serializers import ReturnTextTestimonySerializer, ReturnVideoTestimonySerializer
from rest_framework.views import APIView
from rest_framework.pagination import PageNumberPagination
from django.utils.dateparse import parse_date


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
    
class TextTestimonyViewSet(viewsets.ViewSet):
    
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = StandardResultsSetPagination
    
    @handle_custom_exceptions
    def list(self, request):
        """Get all Text testimonies"""
        
        # Get filter parameter
        status = request.query_params.get("status", "").lower()
        category = request.query_params.get('category', "").lower()
        from_date = request.query_params.get("from")
        to_date = request.query_params.get("to")
        
        # get all texts
        testimony_qs = TextTestimony.objects.all()
        
        if status:
            testimony_qs = testimony_qs.filter(status=status)
            
        if category:
            testimony_qs = testimony_qs.filter(category=category)
            
        # Apply date filtering
        if from_date:
            day, month, year = from_date.split('/')
            formatted_from_date = f"{year}-{month}-{day}"
            parsed_from_date = parse_date(formatted_from_date)
            if parsed_from_date:
                testimony_qs = testimony_qs.filter(created_at__date__gte=parsed_from_date)

        if to_date:
            day, month, year = from_date.split('/')
            formatted_to_date = f"{year}-{month}-{day}"
            parsed_to_date = parse_date(formatted_to_date)
            if parsed_to_date:
                # Set time to the end of the day for inclusivity
                testimony_qs = testimony_qs.filter(created_at__date__lte=parsed_to_date)
        
        paginator = self.pagination_class()
        paginated_queryset = paginator.paginate_queryset(testimony_qs, request)
        serializer = ReturnTextTestimonySerializer(paginated_queryset, many=True)
        
        return paginator.get_paginated_response(serializer.data)
    
    
    @handle_custom_exceptions
    def retrieve(self, request, pk=None):
        """Retrieve a specific testimony by ID"""
        try:
            # Try to fetch the testimony from TextTestimony first
            testimony = TextTestimony.objects.get(id=pk)
            serializer_class = ReturnTextTestimonySerializer
        except TextTestimony.DoesNotExist:
            return CustomResponse.error(
                    message="Testimony not found.",
                    err_code=ErrorCode.NOT_FOUND,
                    status_code=404,
                )
                
        
        # Serialize the testimony and return the response
        serializer = serializer_class(testimony)
        return CustomResponse.success(message="Testimonies retrieved successfully", data=serializer.data, status_code=200)
    
    
    @handle_custom_exceptions
    def update(self, request, pk=None):
        """Update a specific testimony by ID"""
        try:
            # Try to fetch the testimony from TextTestimony first
            testimony = TextTestimony.objects.get(id=pk)
            serializer_class = ReturnTextTestimonySerializer
        except TextTestimony.DoesNotExist:
            return CustomResponse.error(
                    message="Testimony not found.",
                    err_code=ErrorCode.NOT_FOUND,
                    status_code=404,
                )

        # Use the appropriate serializer to validate and update the data
        serializer = serializer_class(testimony, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return CustomResponse.success(message="Testimony deleted successfully", data=serializer.data, status_code=200)

        # Return validation errors if the data is invalid
        return CustomResponse.error(
                    message="Testimony not found.",
                    err_code=ErrorCode.NOT_FOUND,
                    data=serializer.errors,
                    status_code=404,
                )
    
    
    @handle_custom_exceptions
    def destroy(self, request, pk=None):
        """Delete a specific testimony by ID"""
        try:
            # Try to fetch and delete from TextTestimony
            testimony = TextTestimony.objects.get(id=pk, uploaded_by=request.user.id)
        except TextTestimony.DoesNotExist:
           return CustomResponse.error(
                    message="Testimony not found.",
                    err_code=ErrorCode.NOT_FOUND,
                    status_code=404,
                )
        
        # Delete the found testimony
        testimony.delete()
        return CustomResponse.success(message="Testimony deleted successfully", status_code=204)
        

    @handle_custom_exceptions  
    @action(detail=False, methods=['post'])
    def create_text(self, request):
        data = request.data
        data["category"] = data["category"].lower()
        
        serializer = TextTestimonySerializer(data=data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        testimony = serializer.save()
        
        return_serializer = ReturnTextTestimonySerializer(testimony)
        return CustomResponse.success(message="Text testimony added successfully", data=return_serializer.data, status_code=201)
    
    

class VideoTestimonyViewSet(viewsets.ViewSet):
    
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = StandardResultsSetPagination
    
    @handle_custom_exceptions
    def list(self, request):
        """Get all testimonies"""
        
        # Get filter parameter
        status = request.query_params.get("status", "").lower()
        category = request.query_params.get('category', "").lower()
        from_date = request.query_params.get("from")
        to_date = request.query_params.get("to")
        
        # get all videos and 
        testimony_qs = VideoTestimony.objects.all()
        
        if status:
            testimony_qs = testimony_qs.filter(upload_status=status)
            
        if category:
            testimony_qs = testimony_qs.filter(category=category)
            
        # Apply date filtering
        if from_date:
            day, month, year = from_date.split('/')
            formatted_from_date = f"{year}-{month}-{day}"
            parsed_from_date = parse_date(formatted_from_date)
            if parsed_from_date:
                testimony_qs = testimony_qs.filter(created_at__date__gte=parsed_from_date)

        if to_date:
            day, month, year = from_date.split('/')
            formatted_to_date = f"{year}-{month}-{day}"
            parsed_to_date = parse_date(formatted_to_date)
            if parsed_to_date:
                # Set time to the end of the day for inclusivity
                testimony_qs = testimony_qs.filter(created_at__date__lte=parsed_to_date)
            
        
        paginator = self.pagination_class()
        paginated_queryset = paginator.paginate_queryset(testimony_qs, request)
        serializer = ReturnVideoTestimonySerializer(paginated_queryset, many=True, context={'request': request})
        
        return paginator.get_paginated_response(serializer.data)
    
    def retrieve(self, request, pk=None):
        """Retrieve a specific video testimony by ID"""
        try:
            # try fetching it from VideoTestimony
            testimony = VideoTestimony.objects.get(id=pk)
        except VideoTestimony.DoesNotExist:
            # If neither is found, return a 404 response
            return CustomResponse.error(
                    message="Testimony not found.",
                    err_code=ErrorCode.NOT_FOUND,
                    status_code=404,
                )
        
        # Serialize the testimony and return the response
        serializer = ReturnVideoTestimonySerializer(testimony, context={'request': request})
        return Response(serializer.data, status=status.HTTP_200_OK)


    

        
    
    

