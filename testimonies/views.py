from django.conf import settings
from rest_framework.views import APIView
from rest_framework import viewsets
from rest_framework import status, permissions
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import action
from django.utils.dateparse import parse_date
from common.responses import CustomResponse
from notifications.models import Notification
from notifications.serializers import NotificationSerializer
from support.helpers import StandardResultsSetPagination
from user.models import User

from .models import (
    UPLOAD_STATUS,
    InspirationalPictures,
    TextTestimony,
    VideoTestimony,
    TestimonySettings,
    Comment,
)
from django.contrib.contenttypes.models import ContentType

from .serializers import (
    InspirationalPicturesSerializer,
    ReturnATextTestimonyCommentSerializer,
    ReturnInspirationalPicturesSerializer,
    ReturnTextTestimonySerializer,
    ReturnVideoTestimonyCommentSerializer,
    ReturnVideoTestimonyLikeSerializer,
    ReturnVideoTestimonySerializer,
    TextTestimonyCommentSerializer,
    TextTestimonySerializer,
    VideoTestimonyCommentSerializer,
    VideoTestimonySerializer,
    TestimonySettingsSerializer,
    ReturnTextTestimonyLikeSerializer,
)

from common.exceptions import handle_custom_exceptions
from common.error import ErrorCode
from .utils import transform_testimony_files

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
                Q(uploaded_by__full_name__icontains=search)
                | Q(category__icontains=search)
            )

        # Pagination
        paginator = self.pagination_class()
        paginated_queryset = paginator.paginate_queryset(testimony_qs, request)
        serializer = ReturnTextTestimonySerializer(
            paginated_queryset, many=True)

        return paginator.get_paginated_response(serializer.data)


class VideoTestimonyDetailView(APIView):
    """Fetch a specific testimony by ID."""

    def get(self, request, id):
        try:
            testimony = VideoTestimony.objects.get(id=id)
            testimony.views += 1
            testimony.save()

        except VideoTestimony.DoesNotExist:
            return CustomResponse.error(
                message="Testimony not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )

        serializer = ReturnVideoTestimonySerializer(testimony)
        return CustomResponse.success(
            message="Testimony retrieved successfully",
            data=serializer.data,
            status_code=200,
        )


class VideoTestimonyByCategoryView(APIView):
    serializer_class = ReturnVideoTestimonySerializer
    pagination_class = StandardResultsSetPagination

    def get(self, request, category):
        """Get testimonies by category."""
        testimonies = VideoTestimony.objects.filter(category=category)
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
            serializer = self.serializer_class(paginated_queryset, many=True)
            return paginate.get_paginated_response(serializer.data)
        else:
            return CustomResponse.error(
                message="No testimonies found for this category",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )


class VideoTestimonyDeleteSelected(APIView):
    def post(self, request):
        ids = request.data.get("ids", [])
        # print(ids)
        if not ids:
            return CustomResponse.error(
                message="No IDs provided",
                err_code=ErrorCode.BAD_REQUEST,
                status_code=400,
            )
        for id in ids:
            print(f"Processing ID: {id}")
            try:
                video = VideoTestimony.objects.get(id=id)
                print(video.id)
                video.delete()
            except VideoTestimony.DoesNotExist:
                return CustomResponse.error(
                    message=f"Video with ID {id} not found",
                    err_code=ErrorCode.NOT_FOUND,
                    status_code=404,
                )
        return CustomResponse.success(
            message="Testimonies Deleted successfully", status_code=200
        )


class VideoTestimonyCommentsView(APIView):
    # permission_classes = [IsAuthenticated]

    serializer_class = ReturnVideoTestimonyCommentSerializer

    def post(self, request, id):
        user = request.user
        try:
            get_testimony = VideoTestimony.objects.get(id=id)
        except VideoTestimony.DoesNotExist:
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
            get_testimony.comments.create(text=comment, user=user_id)
            content_type = ContentType.objects.get_for_model(VideoTestimony)
            get_testimony.notification.create(
                target=get_testimony.uploaded_by,
                owner=user_id,
                verb=f"{user_id.email} commented on your testimony",
                redirect_url=f"{settings.FRONT_END_BASE_URL}testimonies/video-comment-all/{get_testimony.id}/",
                content_type=content_type,
                object_id=get_testimony.id,
            )
            return CustomResponse.success(
                message="Comment added successfully", status_code=201
            )
        except User.DoesNotExist:
            return CustomResponse.error(
                message="User not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )

    def get(self, request, id):
        get_testimony = VideoTestimony.objects.get(id=id)
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
            message="Comments retrieved successfully", data=payload, status_code=200
        )


class VideoTestimonyReplyComment(APIView):
    # permission_classes = [IsAuthenticated]
    serializer_class = VideoTestimonyCommentSerializer

    def post(self, request, id):
        user = request.user
        comment = request.data.get("comment")
        get_query_param = request.query_params.get("get_testimony")
        get_testimony = VideoTestimony.objects.filter(
            id=get_query_param).first()
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
        except User.DoesNotExist:
            return CustomResponse.error(
                message="User not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )
        # Create the comment
        try:
            content_type = ContentType.objects.get_for_model(Comment)
            reply = Comment.objects.create(
                text=comment, user=user_id, content_type=content_type, object_id=id
            )
            get_comment = Comment.objects.get(id=id)
            get_comment.reply_to.add(reply)
            get_comment.save()
            content_type = ContentType.objects.get_for_model(VideoTestimony)
            get_testimony.notification.create(
                target=get_testimony.uploaded_by,
                owner=user_id,
                verb=f"{user_id.email} commented on your testimony",
                redirect_url=f"{settings.FRONT_END_BASE_URL}testimonies/video-comment-all/{get_testimony.id}/",
                content_type=content_type,
                object_id=get_testimony.id,
            )
            return CustomResponse.success(
                message="Comment added successfully", status_code=201
            )
        except Comment.DoesNotExist:
            return CustomResponse.error(
                message="Comment not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )

    def get(self, request, id):
        try:
            get_testimony = VideoTestimony.objects.get(id=id)
        except VideoTestimony.DoesNotExist:
            return CustomResponse.error(
                message="Testimony not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )
        if not get_testimony:
            return CustomResponse.error(
                message="Testimony not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )
        user_comments = get_testimony.comments.filter(reply_to__isnull=False)
        serializer = self.serializer_class(user_comments, many=True)

        if not serializer:
            return CustomResponse.error(
                message="No comments count found for this testimony",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )
        payload = {
            "comments": serializer.data,
        }
        return CustomResponse.success(
            message="Comments retrieved successfully", data=payload, status_code=200
        )




class VideoTestimonyLikeUserComment(APIView):
    # permission_classes = [IsAuthenticated]

    def post(self, request, id):
        user = request.user
        try:
            user_id = User.objects.get(id=user.id)
            print(user_id.email)
        except User.DoesNotExist:
            return CustomResponse.error(
                message="User not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )
        try:
            comment_id = Comment.objects.get(id=id)
            print(comment_id)
            comment_owner = comment_id.user
            if comment_id.user_like_comment.filter(id=user_id.id).exists():
                comment_id.user_like_comment.remove(user)
                content_type = ContentType.objects.get_for_model(Comment)
                Notification.objects.create(
                    target=comment_owner,
                    owner=user_id,
                    redirect_url=f"{settings.FRONT_END_BASE_URL}testimonies/video-comment-all/{id}/",
                    verb=f"{user_id.email} Unlike your testimony",
                    content_type=content_type,
                    object_id=id,
                )
                return CustomResponse.success(
                    message="user unliked Comment successfully", status_code=200
                )
            else:
                comment_id.user_like_comment.add(user)
                content_type = ContentType.objects.get_for_model(Comment)
                Notification.objects.create(
                    target=comment_owner,
                    owner=user_id,
                    redirect_url=f"{settings.FRONT_END_BASE_URL}testimonies/video-comment-all/{id}/",
                    verb=f"{user_id.email} Like your testimony",
                    content_type=content_type,
                    object_id=id,
                )
                return CustomResponse.success(
                    message="user liked Comment successfully", status_code=201
                )
        except Comment.DoesNotExist:
            return CustomResponse.error(
                message="Comment not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )

    def get(self, request, id):
        try:
            comment = Comment.objects.get(id=id)
            if comment.user_like_comment.all().exists():
                comment_likes = comment.user_like_comment.all().count()
                serializeer = {"likes_count": comment_likes}
                return CustomResponse.success(
                    message="Likes retrieved successfully",
                    data=serializeer,
                    status_code=200,
                )
            else:
                return CustomResponse.error(
                    message="No likes found for this comment",
                    err_code=ErrorCode.NOT_FOUND,
                    status_code=404,
                )
        except Comment.DoesNotExist:
            return CustomResponse.error(
                message="Comment not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )


class VideoTestimonyLikesView(APIView):
    permission_classes = [IsAuthenticated]

    serializer_class = ReturnVideoTestimonyLikeSerializer

    def post(self, request, id):
        user = request.user
        get_testimony = VideoTestimony.objects.get(id=id)
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
            get_testimony.likes.create(user=user_id)
            return CustomResponse.success(
                message="liked Testimony successfully", status_code=201
            )
        except User.DoesNotExist:
            return CustomResponse.error(
                message="User not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )

    def get(self, request, id):
        get_testimony = VideoTestimony.objects.get(id=id)
        print(get_testimony.category)
        if not get_testimony:
            return CustomResponse.error(
                message="Testimony not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )
        serializer = self.serializer_class(get_testimony, many=False)

        if not serializer:
            return CustomResponse.error(
                message="No Likes count found for this testimony",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )
        payload = {
            "testimony": serializer.data,
        }
        return CustomResponse.success(
            message="Likes retrieved successfully", data=payload, status_code=200
        )


class TextTestimonyByCategoryView(APIView):
    serializer_class = ReturnTextTestimonySerializer
    pagination_class = StandardResultsSetPagination

    def get(self, request, category):
        """Get testimonies by category."""
        testimonies = TextTestimony.objects.filter(category=category)
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
            serializer = self.serializer_class(paginated_queryset, many=True)
            return paginate.get_paginated_response(serializer.data)
        else:
            return CustomResponse.error(
                message="No testimonies found for this category",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )


class TextTestimonyDeleteSelected(APIView):
    def post(self, request):
        ids = request.data.get("ids", [])
        print(ids)
        print("Hello world")
        if not ids:
            return CustomResponse.error(
                message="No IDs provided",
                err_code=ErrorCode.BAD_REQUEST,
                status_code=400,
            )
        for id in ids:
            print(f"Processing ID: {id}")
            try:
                video = TextTestimony.objects.get(id=id)
                print(video.id)
                video.delete()
            except TextTestimony.DoesNotExist:
                return CustomResponse.error(
                    message=f"Text with ID {id} not found",
                    err_code=ErrorCode.NOT_FOUND,
                    status_code=404,
                )
        return CustomResponse.success(
            message="Testimonies Deleted successfully", status_code=200
        )


class editTextTestimonyComment(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request, id):
        comment = request.data["comment"]
        user = request.user
        try:
            user_id = User.objects.get(id=user.id)
        except User.DoesNotExist:
            return CustomResponse.error(
                message="User not found", err_code=ErrorCode.NOT_FOUND, status_code=404
            )
        try:
            comment_id = Comment.objects.get(id=id, user=user_id)
            comment_id.text = comment
            comment_id.save()
            return CustomResponse.success(
                message="Comment Updated Successfully", status_code=200
            )
        except Comment.DoesNotExist:
            return CustomResponse.error(
                message="Comment not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )


class TextTestimonyDetailView(APIView):
    """Fetch a specific testimony by ID."""

    permission_classes = [IsAuthenticated]

    def get(self, request, id):
        try:
            testimony = TextTestimony.objects.get(id=id)
            testimony.views += 1
            testimony.save()

        except TextTestimony.DoesNotExist:
            return CustomResponse.error(
                message="Testimony not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )

        serializer = ReturnTextTestimonySerializer(testimony)
        return CustomResponse.success(
            message="Testimony retrieved successfully",
            data=serializer.data,
            status_code=200,
        )

    def put(self, request, id):
        testimony = request.data["testimony"]
        user = request.user
        try:
            user_id = User.objects.get(id=user.id)
        except User.DoesNotExist:
            return CustomResponse.error(
                message="User not not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )
        try:
            testimony_id = TextTestimony.objects.get(
                id=id, uploaded_by=user_id)
            testimony_id.content = testimony
            testimony_id.save()
            return CustomResponse.success(
                message="Testimony Updated successfully", status_code=200
            )
        except TextTestimony.DoesNotExist:
            CustomResponse.error(
                message="Testimony not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )


class GetCommentFromATextTestimony(APIView):
    serializer_class = ReturnATextTestimonyCommentSerializer

    def get(self, request, id):
        comment_id = request.query_params.get("comment_id")
        try:
            testimony = TextTestimony.objects.get(id=id)
            # comment = testimony.comments.get(id=comment_id)
            serializer = ReturnATextTestimonyCommentSerializer(
                testimony,
                many=False,
                context={"request": request, "comment_id": comment_id},
            )
            return CustomResponse.success(
                message="Comment Retrieve", data=serializer.data, status_code=200
            )
        except TextTestimony.DoesNotExist:
            return CustomResponse.error(message="Testimony Not found", status_code=401)


class TextTestimonyCommentsView(APIView):
    permission_classes = [IsAuthenticated]

    serializer_class = TextTestimonyCommentSerializer

    def post(self, request, id):
        user = request.user
        try:
            get_testimony = TextTestimony.objects.get(id=id)
        except TextTestimony.DoesNotExist:
            return CustomResponse.error(
                message="Testimony not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )
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
            comment_id = get_testimony.comments.create(
                text=comment, user=user_id)
            content_type = ContentType.objects.get_for_model(TextTestimony)
            get_testimony.notification.create(
                target=get_testimony.uploaded_by,
                owner=user_id,
                redirect_url=f"{settings.FRONT_END_BASE_URL}get-a-commenttexttestimony/{get_testimony}/?comment_id={comment_id}",
                verb=f"{user_id.email} commented on your testimony",
                content_type=content_type,
                object_id=get_testimony.id,
            )
            return CustomResponse.success(
                message="Comment added successfully", status_code=201
            )
        except User.DoesNotExist:
            return CustomResponse.error(
                message="User not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )

    def get(self, request, id):
        # get_testimony = TextTestimony.objects.get(id=id)
        try:
            get_testimony = TextTestimony.objects.get(id=id)
        except TextTestimony.DoesNotExist:
            return CustomResponse.error(
                message="Testimony not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )
        print(get_testimony.category)
        if not get_testimony:
            return CustomResponse.error(
                message="Testimony not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )
        user_comments = get_testimony.comments
        serializer = self.serializer_class(user_comments, many=True)

        if not serializer:
            return CustomResponse.error(
                message="No comments count found for this testimony",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )
        payload = {
            "comments": serializer.data,
        }
        return CustomResponse.success(
            message="Comments retrieved successfully", data=payload, status_code=200
        )


class TextTestimonyReplyComment(APIView):
    permission_classes = [IsAuthenticated]
    serializer_class = TextTestimonyCommentSerializer

    def post(self, request, id):
        user = request.user
        comment = request.data.get("comment")
        get_query_param = request.query_params.get("get_testimony")
        get_testimony = TextTestimony.objects.filter(
            id=get_query_param).first()
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
        except User.DoesNotExist:
            return CustomResponse.error(
                message="User not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )
        # Create the comment
        try:
            content_type = ContentType.objects.get_for_model(TextTestimony)

            reply = Comment.objects.create(
                text=comment,
                user=user_id,
                content_type=content_type,
                object_id=get_testimony.id,
            )
            print(reply)
            get_comment = Comment.objects.get(id=id)
            get_comment.reply_to.add(reply)
            get_comment.save()

            content_type = ContentType.objects.get_for_model(TextTestimony)
            get_testimony.notification.create(
                target=get_testimony.uploaded_by,
                owner=user_id,
                redirect_url=f"{settings.FRONT_END_BASE_URL}get-a-commenttexttestimony/{get_testimony}/?comment_id={reply.id}",
                verb=f"{user_id.email} Replied commented",
                content_type=content_type,
                object_id=get_testimony.id,
            )
            return CustomResponse.success(
                message="Comment added successfully", status_code=201
            )
        except Comment.DoesNotExist:
            return CustomResponse.error(
                message="Comment not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )

    def get(self, request, id):
        try:
            get_testimony = TextTestimony.objects.get(id=id)
        except TextTestimony.DoesNotExist:
            return CustomResponse.error(
                message="Testimony not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )
        if not get_testimony:
            return CustomResponse.error(
                message="Testimony not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )
        user_comments = get_testimony.comments.filter(reply_to__isnull=False)
        serializer = self.serializer_class(user_comments, many=True)

        if not serializer:
            return CustomResponse.error(
                message="No comments count found for this testimony",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )
        payload = {
            "comments": serializer.data,
        }
        return CustomResponse.success(
            message="Comments retrieved successfully", data=payload, status_code=200
        )


class TextTestimonyLikeUserComment(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, id):
        user = request.user
        try:
            user_id = User.objects.get(id=user.id)
        except User.DoesNotExist:
            return CustomResponse.error(
                message="User not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )
        try:
            comment_id = Comment.objects.get(id=id)
            if comment_id.user_like_comment.filter(id=user_id.id).exists():
                comment_id.user_like_comment.remove(user)
                return CustomResponse.error(
                    message="user unliked Comment successfully",
                    err_code=ErrorCode.NOT_FOUND,
                    status_code=404,
                )
            else:
                comment_id.user_like_comment.add(user)
                return CustomResponse.success(
                    message="user liked Comment successfully", status_code=201
                )
        except Comment.DoesNotExist:
            return CustomResponse.error(
                message="Comment not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )

    def get(self, request, id):
        try:
            comment = Comment.objects.get(id=id)
            print(comment)
            if comment.user_like_comment.all().exists():
                comment_likes = comment.user_like_comment.all().count()
                serializeer = {"likes_count": comment_likes}
                return CustomResponse.success(
                    message="Likes retrieved successfully",
                    data=serializeer,
                    status_code=200,
                )
            else:
                return CustomResponse.error(
                    message="No likes found for this comment",
                    err_code=ErrorCode.NOT_FOUND,
                    status_code=404,
                )
        except Comment.DoesNotExist:
            return CustomResponse.error(
                message="Comment not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )


class TextTestimonyLikesView(APIView):
    # permission_classes = [IsAuthenticated]
    serializer_class = ReturnTextTestimonyLikeSerializer

    def post(self, request, id):
        user = request.user
        try:
            get_testimony = TextTestimony.objects.get(id=id)
            print(get_testimony)
        except TextTestimony.DoesNotExist:
            return CustomResponse.error(
                message="Testimony does not exist",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )
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
            get_testimony.likes.create(user=user_id)
            return CustomResponse.success(
                message="liked Testimony successfully", status_code=201
            )
        except User.DoesNotExist:
            return CustomResponse.error(
                message="User not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )

    def get(self, request, id):
        get_testimony = TextTestimony.objects.get(id=id)
        print(get_testimony.category)
        if not get_testimony:
            return CustomResponse.error(
                message="Testimony not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )
        serializer = self.serializer_class(get_testimony, many=False)

        if not serializer:
            return CustomResponse.error(
                message="No Likes count found for this testimony",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )
        payload = {
            "testimony": serializer.data,
        }
        return CustomResponse.success(
            message="Likes retrieved successfully", data=payload, status_code=200
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
        data = request.data

        video_testimonies = [data]

        total_response_data = []

        for video in video_testimonies:
            transformed_video_data = transform_testimony_files(video)

            serializer = VideoTestimonySerializer(
                data=transformed_video_data, context={"request": request}
            )

            serializer.is_valid(raise_exception=True)
            testimony = serializer.save()

            return_serializer = ReturnVideoTestimonySerializer(
                testimony, context={"request": request}
            )

            total_response_data.append(return_serializer.data)

        return CustomResponse.success(
            message="Success.", data=total_response_data, status_code=201
        )

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
            err_code=ErrorCode.INVALID_ENTRY,
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
        testimony_qs = TextTestimony.objects.filter(uploaded_by=user["id"]).order_by(
            "-created_at"
        )

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
                Q(uploaded_by__full_name__icontains=search)
                | Q(category__icontains=search)
            )

        paginator = self.pagination_class()
        paginated_queryset = paginator.paginate_queryset(testimony_qs, request)
        serializer = ReturnTextTestimonySerializer(
            paginated_queryset, many=True, context={"user": user}
        )
        if serializer:
            return paginator.get_paginated_response(serializer.data)
        else:
            return CustomResponse.error(
                message="No testimonies found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )

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
        print("Hello")
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
            err_code=ErrorCode.INVALID_ENTRY,
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
            return CustomResponse.error(
                message="Sorry, you are not allowed to perform this operation.",
                err_code=ErrorCode.FORBIDDEN,
                status_code=403,
            )

        if (
            user["role"] == "admin" or user["role"] == "super_admin"
        ) and testimony.status == "pending":
            return CustomResponse.error(
                message="You can't delete a pending testimony, please accept or reject it.",
                err_code=ErrorCode.FORBIDDEN,
                status_code=403,
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
        thumbnail = request.data.getlist("thumbnail")
        # print(images)
        if len(thumbnail) > 1:
            # If images are provided, create multiple InspirationalPictures
            total_response_data = []
            for image in thumbnail:
                print(image)
                serializer = InspirationalPicturesSerializer(
                    data={"thumbnail": image}, context={"request": request}
                )
                serializer.is_valid(raise_exception=True)
                testimony = serializer.save()

                return_serializer = ReturnInspirationalPicturesSerializer(
                    testimony, context={"request": request}
                )
                total_response_data.append(return_serializer.data)

            return CustomResponse.success(
                data=total_response_data,
                status_code=201,
            )

        serializer = InspirationalPicturesSerializer(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        if serializer.validated_data.get("status") is None:
            return CustomResponse.error(
                message="Status is required",
                err_code=ErrorCode.INVALID_ENTRY,
                status_code=400,
            )
        testimony = serializer.save()

        return_serializer = ReturnInspirationalPicturesSerializer(
            testimony, context={"request": request}
        )
        return CustomResponse.success(
            data=return_serializer.data,
            status_code=201,
        )

    def list(self, request):
        testimony_qs = InspirationalPictures.objects.all()

        paginator = self.pagination_class()
        paginated_queryset = paginator.paginate_queryset(testimony_qs, request)
        serializer = ReturnInspirationalPicturesSerializer(
            paginated_queryset, many=True, context={"request": request}
        )
        if not serializer:
            return CustomResponse.error(
                message="No inspirational pictures found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
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
            err_code=ErrorCode.INVALID_ENTRY,
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


class ShowAllUplaodInspirationalPicturesByStatus(APIView):
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = StandardResultsSetPagination

    @handle_custom_exceptions
    def get(self, request):
        user = request.user
        try:
            user_id = User.objects.get(id=user.id)
        except User.DoesNotExist:
            return CustomResponse.error(
                message="User not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )
        status = request.query_params.get("status", "").lower()
        if not status:
            return CustomResponse.error(
                message="Status is required",
                err_code=ErrorCode.INVALID_ENTRY,
                status_code=400,
            )
        try:
            if user_id.Roles.VIEWER or user_id.Roles.ADMIN or user_id.Roles.SUPER_ADMIN:
                inspirational_pictures = None
                if status:
                    inspirational_pictures = InspirationalPictures.objects.filter(
                        status=status
                    )
                if not inspirational_pictures:
                    return CustomResponse.error(
                        message="No Inspirational Pictures found",
                        err_code=ErrorCode.NOT_FOUND,
                        status_code=404,
                    )
                paginator = self.pagination_class()
                paginated_queryset = paginator.paginate_queryset(
                    inspirational_pictures, request
                )
                serializer = ReturnInspirationalPicturesSerializer(
                    paginated_queryset, many=True, context={"request": request}
                )
                if not serializer:
                    return CustomResponse.error(
                        message="No inspirational pictures found",
                        err_code=ErrorCode.NOT_FOUND,
                        status_code=404,
                    )
                return paginator.get_paginated_response(serializer.data)
            else:
                return CustomResponse.error(
                    message="You are not allowed to view this resource.",
                    err_code=ErrorCode.FORBIDDEN,
                    status_code=403,
                )
        except User.DoesNotExist:
            return CustomResponse.error(
                message="User not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )


class ShowAllUplaodedInspirationalPictures(APIView):
    """Get all uploaded inspirational pictures."""

    permission_classes = [permissions.IsAuthenticated]
    pagination_class = StandardResultsSetPagination

    def get(self, request):
        user = request.user
        user_id = User.objects.get(id=user.id)
        try:
            if user_id.Roles.VIEWER or user_id.Roles.ADMIN or user_id.Roles.SUPER_ADMIN:
                inspirational_pictures = InspirationalPictures.objects.filter(
                    status=UPLOAD_STATUS.UPLOAD_NOW
                )
                if not inspirational_pictures:
                    return CustomResponse.error(
                        message="No Inspirational Pictures found",
                        err_code=ErrorCode.NOT_FOUND,
                        status_code=404,
                    )
                paginator = self.pagination_class()
                paginated_queryset = paginator.paginate_queryset(
                    inspirational_pictures, request
                )
                serializer = ReturnInspirationalPicturesSerializer(
                    paginated_queryset, many=True, context={"request": request}
                )
                if not serializer:
                    return CustomResponse.error(
                        message="No inspirational pictures found",
                        err_code=ErrorCode.NOT_FOUND,
                        status_code=404,
                    )
                return paginator.get_paginated_response(serializer.data)
            else:
                return CustomResponse.error(
                    message="You are not allowed to view this resource.",
                    err_code=ErrorCode.FORBIDDEN,
                    status_code=403,
                )
        except User.DoesNotExist:
            return CustomResponse.error(
                message="User not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )


class ShowAllInspirationalPicturesStatus(APIView):
    """Get all inspirational pictures status."""

    def get(self, request):
        upload_choices = []
        for choice in UPLOAD_STATUS.choices:
            upload_choices.append(choice[0])
        return CustomResponse.success(
            message="All Inspirational Pictures Status",
            data=upload_choices,
            status_code=200,
        )


class DownloadedInspirationalPictureCountView(APIView):
    """Get the count of downloaded inspirational pictures."""

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, id):
        try:
            picture = InspirationalPictures.objects.get(id=id)
            picture.downloads_count += 1
            picture.save()
            return CustomResponse.success(
                message="Download count updated successfully",
                data={"downloads_count": picture.downloads_count},
                status_code=200,
            )
        except InspirationalPictures.DoesNotExist:
            return CustomResponse.error(
                message="Inspirational Picture not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )


class InpirationalPicturesSharesCount(APIView):
    """Get the count of shares for an inspirational picture."""

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, id):
        try:
            picture = InspirationalPictures.objects.get(id=id)
            picture.shares_count += 1
            picture.save()
            return CustomResponse.success(
                message="Shares count updated successfully",
                data={"shares_count": picture.shares_count},
                status_code=200,
            )
        except InspirationalPictures.DoesNotExist:
            return CustomResponse.error(
                message="Inspirational Picture not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )


class UserLikeInspirationalPicture(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, id):
        user = request.user
        try:
            user_id = User.objects.get(id=user.id)
        except User.DoesNotExist:
            return CustomResponse.error(
                message="User not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )
        try:
            picture = InspirationalPictures.objects.get(id=id)
            if picture.like_inspirational_pic.filter(id=user_id.id).exists():
                picture.like_inspirational_pic.remove(user)
                return CustomResponse.success(
                    message="User unliked the inspirational picture successfully",
                    status_code=200,
                )
            else:
                picture.like_inspirational_pic.add(user)
                return CustomResponse.success(
                    message="User liked the inspirational picture successfully",
                    status_code=201,
                )
        except InspirationalPictures.DoesNotExist:
            return CustomResponse.error(
                message="Inspirational Picture not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
            )

    def get(self, request, id):
        try:
            picture = InspirationalPictures.objects.get(id=id)
            if picture.like_inspirational_pic.all().exists():
                picture_likes = picture.like_inspirational_pic.all().count()
                serializer = {"likes_count": picture_likes}
                return CustomResponse.success(
                    message="Likes retrieved successfully",
                    data=serializer,
                    status_code=200,
                )
            else:
                return CustomResponse.error(
                    message="No likes found for this inspirational picture",
                    err_code=ErrorCode.NOT_FOUND,
                    status_code=404,
                )
        except InspirationalPictures.DoesNotExist:
            return CustomResponse.error(
                message="Inspirational Picture not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404,
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
