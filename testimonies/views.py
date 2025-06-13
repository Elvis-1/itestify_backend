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
from user.models import User
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

from django.db.models import Q


class TextTestimonyListView(APIView):
    """Fetch all testimonies in the db with filtering and search."""
    pagination_class = StandardResultsSetPagination

    def get(self, request):
        # Get filter parameter
        status = request.query_params.get("status", "").lower()
        category = request.query_params.get("category", "").lower()
        from_date = request.query_params.get("from")
        to_date = request.query_params.get("to")
        search = request.query_params.get("search", "").strip()

        # get all texts
        testimony_qs = TextTestimony.objects.all()

        if status:
            testimony_qs = testimony_qs.filter(status=status)

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
                testimony_qs = testimony_qs.filter(
                    created_at__date__lte=parsed_to_date)

        if search:
            testimony_qs = testimony_qs.filter(
                Q(uploaded_by__full_name__icontains=search) |
                Q(category__icontains=search)
            )

        # Pagination
        paginator = self.pagination_class()
        paginated_queryset = paginator.paginate_queryset(testimony_qs, request)
        serializer = ReturnTextTestimonySerializer(
            paginated_queryset, many=True)

        return paginator.get_paginated_response(serializer.data)


class VideoTestimonyByCategoryView(APIView):
    serializer_class = ReturnVideoTestimonySerializer
    pagination_class = StandardResultsSetPagination

    def get(self, request, category):
        """Get testimonies by category."""
        testimonies = VideoTestimony.objects.filter(
            category=category)
        if not testimonies:
            return CustomResponse.error(
                message="No testimonies found for this category",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )

        paginate = self.pagination_class()
        if testimonies:
            paginated_queryset = paginate.paginate_queryset(
                testimonies, request)
            serializer = self.serializer_class(
                paginated_queryset, many=True)
            return paginate.get_paginated_response(serializer.data)
        else:
            return CustomResponse.error(
                message="No testimonies found for this category",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )


class VideoTestimonyCommentsView(APIView):
    # permission_classes = [IsAuthenticated]

    serializer_class = ReturnVideoTestimonySerializer

    def post(self, request, category_comment):
        user = request.user
        get_testimony = VideoTestimony.objects.get(category=category_comment)
        print(get_testimony)
        if not get_testimony:
            return CustomResponse.error(
                message="Testimony not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )
        comment = request.data.get("comment")
        if not comment:
            return CustomResponse.error(
                message="Comment cannot be empty",
                err_code=ErrorCode.BAD_REQUEST,
                status_code=400,
            )
        try:
            user_id = User.objects.get(id=user.id)  # Ensure user exists
            if not user_id.Roles.VIEWER:
                return CustomResponse.error(
                    message="You are not allowed to comment on this testimony.",
                    err_code=ErrorCode.FORBIDDEN,
                    status_code=403,
                )
            # Create the comment
            get_testimony.comments.create(
                text=comment,
                user=user_id
            )
            return CustomResponse.success(
                message="Comment added successfully",
                status_code=201
            )
        except User.DoesNotExist:
            return CustomResponse.error(
                message="User not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )

    def get(self, request, category_comment):
        get_testimony = VideoTestimony.objects.get(category=category_comment)
        if not get_testimony:
            return CustomResponse.error(
                message="Testimony not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )
        serializer = self.serializer_class(get_testimony, many=False)

        if not serializer:
            return CustomResponse.error(
                message="No comments count found for this testimony",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )
        payload = {
            "testimony": serializer.data,
        }
        return CustomResponse.success(
            message="Comments retrieved successfully",
            data=payload,
            status_code=200
        )


class VideoTestimonyLikesView(APIView):
    # permission_classes = [IsAuthenticated]

    def post(self, request, category_like):
        user = request.user
        get_testimony = VideoTestimony.objects.get(category=category_like)
        print(get_testimony)
        if not get_testimony:
            return CustomResponse.error(
                message="Testimony not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )
        try:
            user_id = User.objects.get(id=user.id)  # Ensure user exists
            if not user_id.Roles.VIEWER:
                return CustomResponse.error(
                    message="You are not allowed to comment on this testimony.",
                    err_code=ErrorCode.FORBIDDEN,
                    status_code=403,
                )
            # Create the comment
            is_exist = get_testimony.likes.filter(user=user_id).exists()
            if is_exist:
                get_testimony.likes.filter(user=user_id).delete()
                return CustomResponse.success(
                    message="Unliked Testimony successfully",
                    status_code=200,
                )
            get_testimony.likes.create(
                user=user_id
            )
            return CustomResponse.success(
                message="liked Testimony successfully",
                status_code=201
            )
        except User.DoesNotExist:
            return CustomResponse.error(
                message="User not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )


class TextTestimonyByCategoryView(APIView):
    serializer_class = ReturnTextTestimonySerializer
    pagination_class = StandardResultsSetPagination

    def get(self, request, category):
        """Get testimonies by category."""
        testimonies = TextTestimony.objects.filter(
            category=category)
        if not testimonies:
            return CustomResponse.error(
                message="No testimonies found for this category",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )

        paginate = self.pagination_class()
        if testimonies:
            paginated_queryset = paginate.paginate_queryset(
                testimonies, request)
            serializer = self.serializer_class(
                paginated_queryset, many=True)
            return paginate.get_paginated_response(serializer.data)
        else:
            return CustomResponse.error(
                message="No testimonies found for this category",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )


class TextTestimonyCommentsView(APIView):
    # permission_classes = [IsAuthenticated]

    serializer_class = ReturnTextTestimonySerializer

    def post(self, request, category_comment):
        user = request.user
        get_testimony = TextTestimony.objects.get(category=category_comment)
        print(get_testimony)
        if not get_testimony:
            return CustomResponse.error(
                message="Testimony not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )
        comment = request.data.get("comment")
        if not comment:
            return CustomResponse.error(
                message="Comment cannot be empty",
                err_code=ErrorCode.BAD_REQUEST,
                status_code=400,
            )
        try:
            user_id = User.objects.get(id=user.id)  # Ensure user exists
            if not user_id.Roles.VIEWER:
                return CustomResponse.error(
                    message="You are not allowed to comment on this testimony.",
                    err_code=ErrorCode.FORBIDDEN,
                    status_code=403,
                )
            # Create the comment
            get_testimony.comments.create(
                text=comment,
                user=user_id
            )
            return CustomResponse.success(
                message="Comment added successfully",
                status_code=201
            )
        except User.DoesNotExist:
            return CustomResponse.error(
                message="User not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )

    def get(self, request, category):
        get_testimony = TextTestimony.objects.get(category=category)
        if not get_testimony:
            return CustomResponse.error(
                message="Testimony not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )
        serializer = self.serializer_class(get_testimony, many=False)

        if not serializer:
            return CustomResponse.error(
                message="No comments count found for this testimony",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )
        payload = {
            "testimony": serializer.data,
        }
        return CustomResponse.success(
            message="Comments retrieved successfully",
            data=payload,
            status_code=200
        )


class TextTestimonyLikesView(APIView):
    # permission_classes = [IsAuthenticated]

    def post(self, request, category_like):
        user = request.user
        get_testimony = TextTestimony.objects.get(category=category_like)
        print(get_testimony)
        if not get_testimony:
            return CustomResponse.error(
                message="Testimony not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )
        try:
            user_id = User.objects.get(id=user.id)  # Ensure user exists
            if not user_id.Roles.VIEWER:
                return CustomResponse.error(
                    message="You are not allowed to comment on this testimony.",
                    err_code=ErrorCode.FORBIDDEN,
                    status_code=403,
                )
            # Create the comment
            is_exist = get_testimony.likes.filter(user=user_id).exists()
            if is_exist:
                get_testimony.likes.filter(user=user_id).delete()
                return CustomResponse.success(
                    message="Unliked Testimony successfully",
                    status_code=200,
                )
            get_testimony.likes.create(
                user=user_id
            )
            return CustomResponse.success(
                message="liked Testimony successfully",
                status_code=201
            )
        except User.DoesNotExist:
            return CustomResponse.error(
                message="User not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )


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
            testimony.status = "approved"
            testimony.rejection_reason = ""
        elif action == "reject":
            if rejection_reason == "":
                return CustomResponse.error(
                    message="Please provide a rejection reason",
                    err_code=ErrorCode.BAD_REQUEST,
                    status_code=400,
                )
            testimony.status = "rejected"
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

    @handle_custom_exceptions
    @action(detail=False, methods=["post"])
    def create_video(self, request):
        video_testimonies = request.data["video_testimonies"]
        total_response_data = []

        for video in video_testimonies:
            serializer = VideoTestimonySerializer(
                data=video, context={"request": request}
            )
            serializer.is_valid(raise_exception=True)
            serializer = ""

        for video in video_testimonies:
            serializer = VideoTestimonySerializer(
                data=video, context={"request": request}
            )

            serializer.is_valid(raise_exception=True)
            testimony = serializer.save()

            return_serializer = ReturnVideoTestimonySerializer(
                testimony, context={"request": request}
            )

            total_response_data.append(return_serializer.data)
        return CustomResponse.success(data=total_response_data, status_code=201)

    def list(self, request):
        """Get all testimonies"""

        # Get filter parameter
        upload_status = request.query_params.get("upload_status", "").lower()
        category = request.query_params.get("category", "").lower()
        from_date = request.query_params.get("from")
        to_date = request.query_params.get("to")
        search = request.query_params.get("search", "").strip()

        # get all videos and
        testimony_qs = VideoTestimony.objects.all().order_by("-created_at")

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
                testimony_qs = testimony_qs.filter(
                    created_at__date__lte=parsed_to_date)

        paginator = self.pagination_class()
        paginated_queryset = paginator.paginate_queryset(testimony_qs, request)

        serializer = ReturnVideoTestimonySerializer(
            paginated_queryset, many=True, context={"request": request}
        )

        return paginator.get_paginated_response(serializer.data)

    @handle_custom_exceptions
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

    @handle_custom_exceptions
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
        """Get all Text testimonies for the logged in user."""
        user = request.user_data

        # Get filter parameter
        status = request.query_params.get("status", "").lower()
        category = request.query_params.get("category", "").lower()
        from_date = request.query_params.get("from")
        to_date = request.query_params.get("to")
        search = request.query_params.get("search", "").strip()

        # get all texts
        testimony_qs = TextTestimony.objects.filter(
            uploaded_by=user["id"]).order_by("-created_at")

        if status:
            testimony_qs = testimony_qs.filter(status=status)

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
                testimony_qs = testimony_qs.filter(
                    created_at__date__lte=parsed_to_date)

        if search:
            testimony_qs = testimony_qs.filter(
                Q(uploaded_by__full_name__icontains=search) |
                Q(category__icontains=search)
            )

        paginator = self.pagination_class()
        paginated_queryset = paginator.paginate_queryset(testimony_qs, request)
        serializer = ReturnTextTestimonySerializer(
            paginated_queryset, many=True, context={"user": user})

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
        serializer = TextTestimonySerializer(
            testimony, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return_serializer = ReturnTextTestimonySerializer(
                serializer.instance)

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
        user = request.user_data

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

        if user["role"] == "viewer" and user["id"] != testimony.uploaded_by.id:
            return CustomResponse.error(message="Sorry, you are not allowed to perform this operation.", err_code=ErrorCode.FORBIDDEN, status_code=403)

        if (user["role"] == "admin" or user["role"] == "super_admin") and testimony.status == "pending":
            return CustomResponse.error(message="You can't delete a pending testimony, please accept or reject it.", err_code=ErrorCode.FORBIDDEN, status_code=403)

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
                testimony_qs = testimony_qs.filter(
                    created_at__date__lte=parsed_to_date)

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
