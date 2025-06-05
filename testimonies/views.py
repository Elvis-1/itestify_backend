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
from .models import (
    InspirationalPictures,
    TextTestimony,
    VideoTestimony,
    TestimonySettings,
)
from .serializers import (
    InspirationalPicturesSerializer,
    ReturnInspirationalPicturesSerializer,
    ReturnTextTestimonySerializer,
    ReturnVideoTestimonySerializer,
    TextTestimonySerializer,
    VideoTestimonySerializer,
    TestimonySettingsSerializer,
)

from .permissions import IsAuthenticated, IsLoggedInUser
from common.exceptions import handle_custom_exceptions
from common.responses import CustomResponse
from common.error import ErrorCode
from .tasks import upload_video


class TextTestimonyListView(APIView):
    """Fetch all testimonies with filtering and search."""

    def get(self, request):
        testimonies = TextTestimony.objects.all()
        # Filters
        category = request.query_params.get("category")
        status_filter = request.query_params.get("status")
        search = request.query_params.get("search")
        start_date = request.query_params.get("start_date")
        end_date = request.query_params.get("end_date")

        if category:
            testimonies = testimonies.filter(category=category)
        if status_filter:
            testimonies = testimonies.filter(status=status_filter)
        if search:
            testimonies = testimonies.filter(name__icontains=search)
        if start_date and end_date:
            testimonies = testimonies.filter(
                date_submitted__range=[start_date, end_date]
            )

        # Pagination
        paginator = PageNumberPagination()
        paginator.page_size = 10
        paginated_testimonies = paginator.paginate_queryset(request, testimonies)

        # Serialize and return
        serializer = TextTestimonySerializer(paginated_testimonies, many=True)
        return paginator.get_paginated_response(serializer.data)


class TextTestimonyApprovalView(APIView):
    """Approve or reject testimonies."""

    def post(self, request, pk):
        try:
            testimony = TextTestimony.objects.get(pk=pk)
        except TextTestimony.DoesNotExist:
            return CustomResponse.error(
                message="Testimony not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )

        action = request.data.get("action")  # 'approve' or 'reject'
        rejection_reason = request.data.get("rejection_reason", "")

        if action == "approve":
            testimony.status = "Approved"
            testimony.rejection_reason = ""
        elif action == "reject":
            if rejection_reason == "":
                return CustomResponse.error(
                    message="Please provide a rejection reason",
                    err_code=ErrorCode.BAD_REQUEST,
                    status_code=400,
                )
            testimony.status = "Rejected"
            testimony.rejection_reason = rejection_reason
        else:
            return CustomResponse.error(
                message="Invalid action",
                err_code=ErrorCode.INVALID_ACTION,
                status_code=400,
            )

        testimony.save()
        return CustomResponse.success(
            message="Testimony updated successfully", status_code=200
        )


class TestimonySettingsView(APIView):
    """Manage global settings."""

    serializer_class = TestimonySettingsSerializer
    permission_classes = [IsAuthenticated]

    @handle_custom_exceptions
    def get(self, request):
        settings = TestimonySettings.objects.all()
        serializer = self.serializer_class(settings, many=True)
        return CustomResponse.success(message="Global settings.", data=serializer.data)

    def put(self, request):
        data = request.data
        settings = TestimonySettings.objects.all().first()
        settings.notify_admin = data["notify_admin"]
        settings.save()
        return CustomResponse.success(
            message="Settings updated successfully", status_code=200
        )

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        settings = TestimonySettings.objects.all()

        if settings:
            return CustomResponse.error(
                message="Testimony settings already exist.",
                err_code="testimony_settings_exists",
                status_code=400,
            )

        TestimonySettings.objects.create(**serializer.validated_data)

        return CustomResponse.success(
            message="Testimony settings created successfully.", status_code=200
        )


class VideoTestimonyViewSet(viewsets.ViewSet):

    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPagination

    @action(detail=False, methods=["post"])
    def create_video(self, request):
        serializer = VideoTestimonySerializer(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        testimony = serializer.save()

        return_serializer = ReturnVideoTestimonySerializer(
            testimony, context={"request": request}
        )
        return CustomResponse.success(data=return_serializer.data, status_code=201)

    def list(self, request):
        """Get all testimonies"""

        # Get filter parameter
        upload_status = request.query_params.get("upload_status", "").lower()
        category = request.query_params.get("category", "").lower()
        from_date = request.query_params.get("from")
        to_date = request.query_params.get("to")

        # get all videos and
        testimony_qs = VideoTestimony.objects.all()
        print(testimony_qs)
        if upload_status:
            testimony_qs = testimony_qs.filter(upload_status=upload_status)

        if category:
            testimony_qs = testimony_qs.filter(category=category)

        # Apply date filtering
        if from_date:
            parsed_from_date = parse_date(from_date)
            if parsed_from_date:
                testimony_qs = testimony_qs.filter(
                    created_at__date__gte=parsed_from_date
                )

        if to_date:
            parsed_to_date = parse_date(to_date)
            if parsed_to_date:
                # Set time to the end of the day for inclusivity
                testimony_qs = testimony_qs.filter(created_at__date__lte=parsed_to_date)

        paginator = self.pagination_class()
        paginated_queryset = paginator.paginate_queryset(testimony_qs, request)

        serializer = ReturnVideoTestimonySerializer(
            paginated_queryset, many=True, context={"request": request}
        )

        return paginator.get_paginated_response(serializer.data)

    def retrieve(self, request, pk=None):
        """Retrieve a specific video testimony by ID"""
        try:
            # try fetching it from VideoTestimony
            testimony = VideoTestimony.objects.get(id=pk)
        except VideoTestimony.DoesNotExist:
            # If neither is found, return a 404 response
            return CustomResponse.error(
                message="Testimony not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )

        # Serialize the testimony and return the response
        serializer = ReturnVideoTestimonySerializer(
            testimony, context={"request": request}
        )
        return CustomResponse.success(
            message="Testimony retrieved successfully",
            data=serializer.data,
            status_code=200,
        )

    def update(self, request, pk=None):
        """Update a specific video testimony by ID"""
        try:
            # try fetching it from VideoTestimony
            testimony = VideoTestimony.objects.get(id=pk)
        except VideoTestimony.DoesNotExist:
            # If neither is found, return a 404 response
            return CustomResponse.error(
                message="Testimony not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=400,
            )

        # Use the appropriate serializer to validate and update the data
        serializer = VideoTestimonySerializer(
            testimony, data=request.data, partial=True
        )
        if serializer.is_valid():
            serializer.save()
            return_serializer = ReturnVideoTestimonySerializer(
                serializer.instance, context={"request": request}
            )
            return CustomResponse.success(
                message="Testimony updated successfully",
                data=return_serializer.data,
                status_code=200,
            )

        # Return validation errors if the data is invalid
        return CustomResponse.error(
            message=serializer.errors,
            err_code=ErrorCode.VALIDATION_ERROR,
            status_code=400,
        )

    def destroy(self, request, pk=None):
        """Delete a specific video testimony by ID"""
        try:
            testimony = VideoTestimony.objects.get(id=pk)
        except VideoTestimony.DoesNotExist:
            # If neither is found, return a 404 response
            return CustomResponse.error(
                message="Testimony not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )

        # Delete the found testimony
        testimony.delete()
        return CustomResponse.success(
            message="Testimony deleted successfully",
            status_code=204,
        )


class TextTestimonyViewSet(viewsets.ViewSet):

    permission_classes = [
        permissions.IsAuthenticated,
    ]
    pagination_class = StandardResultsSetPagination

    def list(self, request):
        """Get all Text testimonies"""

        # Get filter parameter
        status = request.query_params.get("type", "").lower()
        category = request.query_params.get("category", "").lower()
        from_date = request.query_params.get("from_date")
        to_date = request.query_params.get("to_date")
        user_id = request.query_params.get("user_id")

        # get all texts
        testimony_qs = TextTestimony.objects.all()

        if status:
            testimony_qs = testimony_qs.filter(status=status)

        if category:
            testimony_qs = testimony_qs.filter(category=category)

        if user_id:
            testimony_qs = testimony_qs.filter(uploaded_by=user_id)

        # Apply date filtering
        if from_date:
            parsed_from_date = parse_date(from_date)
            if parsed_from_date:
                testimony_qs = testimony_qs.filter(
                    created_at__date__gte=parsed_from_date
                )

        if to_date:
            parsed_to_date = parse_date(to_date)
            if parsed_to_date:
                # Set time to the end of the day for inclusivity
                testimony_qs = testimony_qs.filter(created_at__date__lte=parsed_to_date)

        paginator = self.pagination_class()
        paginated_queryset = paginator.paginate_queryset(testimony_qs, request)
        serializer = ReturnTextTestimonySerializer(paginated_queryset, many=True)

        return paginator.get_paginated_response(serializer.data)

    def retrieve(self, request, pk=None):
        """Retrieve a specific text testimony by ID"""
        try:
            # try fetching it from TextTestimony
            testimony = TextTestimony.objects.get(id=pk)
        except TextTestimony.DoesNotExist:
            # If neither is found, return a 404 response
            return CustomResponse.error(
                message="Testimony not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )

        # Serialize the testimony and return the response
        serializer = ReturnTextTestimonySerializer(testimony)
        return CustomResponse.success(
            data=serializer.data,
            status_code=200,
        )

    @handle_custom_exceptions
    @action(detail=False, methods=["post"])
    def create_text(self, request):

        serializer = TextTestimonySerializer(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        testimony = serializer.save()

        return_serializer = ReturnTextTestimonySerializer(testimony)

        return CustomResponse.success(
            message="Testimony created successfully",
            data=return_serializer.data,
            status_code=201,
        )

    def update(self, request, pk=None):
        """Update a specific text testimony by ID"""
        try:
            testimony = TextTestimony.objects.get(id=pk)
        except TextTestimony.DoesNotExist:
            return CustomResponse.error(
                message="Testimony not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=status.HTTP_404_NOT_FOUND,
            )

        # Use the appropriate serializer to validate and update the data
        serializer = TextTestimonySerializer(testimony, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return_serializer = ReturnTextTestimonySerializer(serializer.instance)

            return CustomResponse.success(
                data=return_serializer.data,
                status_code=200,
            )

        # Return validation errors if the data is invalid
        return CustomResponse.error(
            message=serializer.errors,
            err_code=ErrorCode.VALIDATION_ERROR,
            status_code=400,
        )

    def destroy(self, request, pk=None):
        """Delete a specific text testimony by ID"""
        try:
            testimony = TextTestimony.objects.get(id=pk)
        except TextTestimony.DoesNotExist:
            # If neither is found, return a 404 response
            return CustomResponse.error(
                message="Testimony not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )

        # Delete the found testimony
        testimony.delete()
        return CustomResponse.success(
            message="Success.",
            status_code=200,
        )


class InspirationalPicturesViewSet(viewsets.ViewSet):
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = StandardResultsSetPagination

    @action(detail=False, methods=["post"])
    def create_pic(self, request):

        serializer = InspirationalPicturesSerializer(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        testimony = serializer.save()

        return_serializer = ReturnInspirationalPicturesSerializer(
            testimony, context={"request": request}
        )
        return CustomResponse.success(
            data=return_serializer.data,
            status_code=201,
        )

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
            day, month, year = from_date.split("/")
            formatted_from_date = f"{year}-{month}-{day}"
            parsed_from_date = parse_date(formatted_from_date)

            if parsed_from_date:
                testimony_qs = testimony_qs.filter(
                    created_at__date__gte=parsed_from_date
                )

        if to_date:
            day, month, year = from_date.split("/")
            formatted_from_date = f"{year}-{month}-{day}"
            parsed_to_date = parse_date(formatted_from_date)
            if parsed_to_date:
                # Set time to the end of the day for inclusivity
                testimony_qs = testimony_qs.filter(created_at__date__lte=parsed_to_date)

        paginator = self.pagination_class()
        paginated_queryset = paginator.paginate_queryset(testimony_qs, request)
        serializer = ReturnInspirationalPicturesSerializer(
            paginated_queryset, many=True, context={"request": request}
        )

        return paginator.get_paginated_response(serializer.data)

    def retrieve(self, request, pk=None):

        # get inspirational pic
        try:
            inspirational_pic = InspirationalPictures.objects.get(id=pk)
        except InspirationalPictures.DoesNotExist:
            return CustomResponse.error(
                message="Inspirational Picture with this Id Does not Exist",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )

        serializer = ReturnInspirationalPicturesSerializer(
            inspirational_pic, context={"request": request}
        )

        # Serialize the testimony and return the response
        return CustomResponse.success(
            message="Inspirational Picture retrieved successfully",
            data=serializer.data,
            status_code=200,
        )

    def update(self, request, pk=None):
        # get inspirational pic
        try:
            inspirational_pic = InspirationalPictures.objects.get(id=pk)
        except InspirationalPictures.DoesNotExist:
            return CustomResponse.error(
                message="Inspirational Picture with this ID Does not Exist",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )

        serializer = InspirationalPicturesSerializer(
            inspirational_pic, data=request.data, partial=True
        )
        if serializer.is_valid():
            serializer.save()
            return_serializer = ReturnInspirationalPicturesSerializer(
                serializer.instance, context={"request": request}
            )
            return CustomResponse.success(
                data=return_serializer.data,
                status_code=200,
            )

        # Return validation errors if the data is invalid
        return CustomResponse.error(
            message=serializer.errors,
            err_code=ErrorCode.VALIDATION_ERROR,
            status_code=400,
        )

    def destroy(self, request, pk=None):
        # get inspirational pic
        try:
            inspirational_pic = InspirationalPictures.objects.get(id=pk)
        except InspirationalPictures.DoesNotExist:
            return CustomResponse.error(
                message="Inspirational Picture with this ID Does not Exist",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )

        # Delete the found inspitrational pic
        inspirational_pic.delete()
        return CustomResponse.success(
            message="Inspirational Picture deleted successfully",
            status_code=204,
        )


# class TestimonySettingsView(APIView):
#     """Manage global settings."""

#     def get(self, request):
#         settings = {
#             "likes_enabled": True,
#             "comments_enabled": True,
#             "shares_enabled": True
#         }
#         return Response(settings)

#     def post(self, request):
#         # Update settings logic here
#         return Response({"message": "Settings updated successfully"})
