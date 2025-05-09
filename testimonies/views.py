
from rest_framework.views import APIView
from rest_framework import viewsets
from rest_framework import status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.pagination import PageNumberPagination
from rest_framework import status
from django.utils.dateparse import parse_date
from common.responses import CustomResponse
from support import http
from support.helpers import StandardResultsSetPagination
from .models import InspirationalPictures, TextTestimony, VideoTestimony, TestimonySettings
from .serializers import InspirationalPicturesSerializer, ReturnInspirationalPicturesSerializer, ReturnTextTestimonySerializer, ReturnVideoTestimonySerializer, TextTestimonySerializer, VideoTestimonySerializer, TestimonySettingsSerializer

from .permissions import IsAuthenticated
from common.exceptions import handle_custom_exceptions
from .tasks import upload_video


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
            testimonies = testimonies.filter(
                date_submitted__range=[start_date, end_date])

        # Pagination
        paginator = PageNumberPagination()
        paginator.page_size = 10
        paginated_testimonies = paginator.paginate_queryset(
            testimonies, request)

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
            if rejection_reason == "":
                return Response({"error": "Please provide a rejection reason"}, status=status.HTTP_400_BAD_REQUEST)
            testimony.status = 'Rejected'
            testimony.rejection_reason = rejection_reason
        else:
            return Response({"error": "Invalid action"}, status=status.HTTP_400_BAD_REQUEST)

        testimony.save()
        return Response({"message": "Testimony updated successfully"})


class TestimonySettingsView(APIView):
    """Manage global settings."""
    serializer_class = TestimonySettingsSerializer
    permission_classes = [IsAuthenticated]

    @handle_custom_exceptions
    def get(self, request):
        settings = TestimonySettings.objects.all()
        serializer = self.serializer_class(settings, many=True)
        return Response({
            "message": "Global settings.",
            "data": serializer.data
        })

    def put(self, request):
        data = request.data
        settings = TestimonySettings.objects.all().first()
        settings.notify_admin = data["notify_admin"]
        settings.save()
        return Response({"message": "Settings updated successfully"})

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        settings = TestimonySettings.objects.all()

        if settings:
            return Response({"error": "Testimony already exists."}, status=status.HTTP_400_BAD_REQUEST)

        TestimonySettings.objects.create(**serializer.validated_data)

        return Response({"message": "Successful."})


class VideoTestimonyViewSet(viewsets.ViewSet):

    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPagination

    @action(detail=False, methods=['post'])
    def create_video(self, request):
        serializer = VideoTestimonySerializer(
            data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        testimony = serializer.save()

        return_serializer = ReturnVideoTestimonySerializer(
            testimony, context={'request': request})
        return http.success_response(data=return_serializer.data, status_code=status.HTTP_201_CREATED)

    def list(self, request):
        """Get all testimonies"""

        # Get filter parameter
        status = request.query_params.get("type", "").lower()
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
                testimony_qs = testimony_qs.filter(
                    created_at__date__gte=parsed_from_date)

        if to_date:
            day, month, year = from_date.split('/')
            formatted_to_date = f"{year}-{month}-{day}"
            parsed_to_date = parse_date(formatted_to_date)
            if parsed_to_date:
                # Set time to the end of the day for inclusivity
                testimony_qs = testimony_qs.filter(
                    created_at__date__lte=parsed_to_date)

        paginator = self.pagination_class()
        paginated_queryset = paginator.paginate_queryset(testimony_qs, request)
        serializer = ReturnVideoTestimonySerializer(
            paginated_queryset, many=True, context={'request': request})

        return paginator.get_paginated_response(serializer.data)

    def retrieve(self, request, pk=None):
        """Retrieve a specific video testimony by ID"""
        try:
            # try fetching it from VideoTestimony
            testimony = VideoTestimony.objects.get(id=pk)
        except VideoTestimony.DoesNotExist:
            # If neither is found, return a 404 response
            return http.failed_response(
                message="Testimony not found.",
                status_code=status.HTTP_404_NOT_FOUND,
            )

        # Serialize the testimony and return the response
        serializer = ReturnVideoTestimonySerializer(
            testimony, context={'request': request})
        return Response(serializer.data, status=status.HTTP_200_OK)

    def update(self, request, pk=None):
        """Update a specific video testimony by ID"""
        try:
            # try fetching it from VideoTestimony
            testimony = VideoTestimony.objects.get(id=pk)
        except VideoTestimony.DoesNotExist:
            # If neither is found, return a 404 response
            return http.failed_response(
                message="Testimony not found.",
                status_code=status.HTTP_404_NOT_FOUND,
            )

        # Use the appropriate serializer to validate and update the data
        serializer = VideoTestimonySerializer(
            testimony, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return_serializer = ReturnVideoTestimonySerializer(
                serializer.instance, context={'request': request})
            return http.success_response(data=return_serializer.data, status_code=status.HTTP_200_OK)

        # Return validation errors if the data is invalid
        return http.failed_response(message=serializer.errors, status_code=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        """Delete a specific video testimony by ID"""
        try:
            testimony = VideoTestimony.objects.get(id=pk)
        except VideoTestimony.DoesNotExist:
            # If neither is found, return a 404 response
            return http.failed_response(
                message="Video Testimony not found.",
                status_code=status.HTTP_404_NOT_FOUND,
            )

        # Delete the found testimony
        testimony.delete()
        return http.success_response(message="Testimony deleted successfully.", status_code=status.HTTP_204_NO_CONTENT,
                                     )


class TextTestimonyViewSet(viewsets.ViewSet):

    permission_classes = [permissions.IsAuthenticated]
    pagination_class = StandardResultsSetPagination

    def list(self, request):
        """Get all Text testimonies"""

        # Get filter parameter
        status = request.query_params.get("type", "").lower()
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
                testimony_qs = testimony_qs.filter(
                    created_at__date__gte=parsed_from_date)

        if to_date:
            day, month, year = from_date.split('/')
            formatted_to_date = f"{year}-{month}-{day}"
            parsed_to_date = parse_date(formatted_to_date)
            if parsed_to_date:
                # Set time to the end of the day for inclusivity
                testimony_qs = testimony_qs.filter(
                    created_at__date__lte=parsed_to_date)

        paginator = self.pagination_class()
        paginated_queryset = paginator.paginate_queryset(testimony_qs, request)
        serializer = ReturnTextTestimonySerializer(
            paginated_queryset, many=True)

        return paginator.get_paginated_response(serializer.data)

    def retrieve(self, request, pk=None):
        """Retrieve a specific text testimony by ID"""
        try:
            # try fetching it from TextTestimony
            testimony = TextTestimony.objects.get(id=pk)
        except TextTestimony.DoesNotExist:
            # If neither is found, return a 404 response
            return http.failed_response(
                message="Testimony not found.",
                status_code=status.HTTP_404_NOT_FOUND,
            )

        # Serialize the testimony and return the response
        serializer = ReturnTextTestimonySerializer(testimony)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=False, methods=['post'])
    def create_text(self, request):

        serializer = TextTestimonySerializer(
            data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        testimony = serializer.save()

        return_serializer = ReturnTextTestimonySerializer(testimony)
        return http.success_response(data=return_serializer.data, status_code=status.HTTP_201_CREATED)

    def update(self, request, pk=None):
        """Update a specific text testimony by ID"""
        try:
            testimony = TextTestimony.objects.get(id=pk)
        except TextTestimony.DoesNotExist:
            return http.failed_response(
                message="Testimony not found.",
                status_code=status.HTTP_404_NOT_FOUND,
            )

        # Use the appropriate serializer to validate and update the data
        serializer = TextTestimonySerializer(
            testimony, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return_serializer = ReturnTextTestimonySerializer(
                serializer.instance)
            return http.success_response(data=return_serializer.data, status_code=status.HTTP_200_OK)

        # Return validation errors if the data is invalid
        return http.failed_response(message=serializer.errors, status_code=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        """Delete a specific text testimony by ID"""
        try:
            testimony = TextTestimony.objects.get(id=pk)
        except TextTestimony.DoesNotExist:
            # If neither is found, return a 404 response
            return http.failed_response(
                message="text Testimony not found.",
                status_code=status.HTTP_404_NOT_FOUND,
            )

        # Delete the found testimony
        testimony.delete()
        return http.success_response(message="Testimony deleted successfully.", status_code=status.HTTP_204_NO_CONTENT,
                                     )


class InspirationalPicturesViewSet(viewsets.ViewSet):

    permission_classes = [permissions.IsAuthenticated]
    pagination_class = StandardResultsSetPagination

    @action(detail=False, methods=['post'])
    def create_pic(self, request):

        serializer = InspirationalPicturesSerializer(
            data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        testimony = serializer.save()

        return_serializer = ReturnInspirationalPicturesSerializer(
            testimony, context={'request': request})
        return http.success_response(data=return_serializer.data, status_code=status.HTTP_201_CREATED)

    def list(self, request):
        # Get filter parameter
        status = request.query_params.get("type", "").lower()
        from_date = request.query_params.get("from")
        to_date = request.query_params.get("to")

        # get all inspiration pics
        testimony_qs = InspirationalPictures.objects.all()

        if status:
            testimony_qs = testimony_qs.filter(upload_status=status)

        # Apply date filtering
        if from_date:
            day, month, year = from_date.split('/')
            formatted_from_date = f"{year}-{month}-{day}"
            parsed_from_date = parse_date(formatted_from_date)

            if parsed_from_date:
                testimony_qs = testimony_qs.filter(
                    created_at__date__gte=parsed_from_date)

        if to_date:
            day, month, year = from_date.split('/')
            formatted_from_date = f"{year}-{month}-{day}"
            parsed_to_date = parse_date(formatted_from_date)
            if parsed_to_date:
                # Set time to the end of the day for inclusivity
                testimony_qs = testimony_qs.filter(
                    created_at__date__lte=parsed_to_date)

        paginator = self.pagination_class()
        paginated_queryset = paginator.paginate_queryset(testimony_qs, request)
        serializer = ReturnInspirationalPicturesSerializer(
            paginated_queryset, many=True, context={'request': request})

        return paginator.get_paginated_response(serializer.data)

    def retrieve(self, request, pk=None):

        # get inspirational pic
        try:
            inspirational_pic = InspirationalPictures.objects.get(id=pk)
        except InspirationalPictures.DoesNotExist:
            return http.failed_response(message="Inspirational Picture with this ID Does not Exist", status_code=status.HTTP_404_NOT_FOUND)

        serializer = ReturnInspirationalPicturesSerializer(
            inspirational_pic, context={"request": request})

        return http.success_response(data=serializer.data, status_code=status.HTTP_200_OK)

    def update(self, request, pk=None):
        # get inspirational pic
        try:
            inspirational_pic = InspirationalPictures.objects.get(id=pk)
        except InspirationalPictures.DoesNotExist:
            return http.failed_response(message="Inspirational Picture with this ID Does not Exist", status_code=status.HTTP_404_NOT_FOUND)

        serializer = InspirationalPicturesSerializer(
            inspirational_pic, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return_serializer = ReturnInspirationalPicturesSerializer(
                serializer.instance, context={"request": request})
            return http.success_response(data=return_serializer.data, status_code=status.HTTP_200_OK)

        # Return validation errors if the data is invalid
        return http.failed_response(message=serializer.errors, status_code=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        # get inspirational pic
        try:
            inspirational_pic = InspirationalPictures.objects.get(id=pk)
        except InspirationalPictures.DoesNotExist:
            return http.failed_response(message="Inspirational Picture with this ID Does not Exist", status_code=status.HTTP_404_NOT_FOUND)

        # Delete the found inspitrational pic
        inspirational_pic.delete()
        return http.success_response(message="Inspirational Picture deleted successfully.", status_code=status.HTTP_204_NO_CONTENT)
