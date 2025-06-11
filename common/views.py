import os
import cloudinary.uploader

from .responses import CustomResponse
from .serializers import MediaUploadSerializer
from .error import ErrorCode

from rest_framework.views import APIView
from rest_framework.decorators import api_view

from django.utils.timezone import now

MAX_FILE_SIZE = 50 * 1024 * 1024


@api_view(["GET"])
def health_check(request):
    return CustomResponse.success(message="Server Active.", status_code=200, data={"now": now()})

class MediaUploadViewAPIView(APIView):
    def post(self, request, *args, **kwargs):
        files = request.FILES.getlist("files")

        if not files:
            return CustomResponse.error(
                err_code=ErrorCode.BAD_REQUEST, message="At least one file is required."
            )

        uploaded_files = []

        for file in files:
            # determine file type and validate
            is_video = file.content_type.startswith("video/")
            is_image = file.content_type.startswith("image/")

            if not (is_video or is_image):
                return CustomResponse.error(
                    message=f"Invalid file type for {file.name}",
                    err_code=ErrorCode.BAD_REQUEST,
                    status_code=400,
                )

            # check if the file size exceed the max file size
            if file.size > MAX_FILE_SIZE:
                return CustomResponse.error(
                    err_code=ErrorCode.INVALID_VALUE,
                    message=f"The file {file.name} exceeds the file limit of 50MB.",
                    status_code=400,
                )

            resource_type = "video" if is_video else "image"

            upload_result = cloudinary.uploader.upload_large(
                file, folder="media", resource_type=resource_type, chunk_size=6000000
            )

            uploaded_files.append(
                {
                    "url": upload_result["url"],
                    "file_name": file.name,
                    "type": resource_type,
                }
            )

        return CustomResponse.success(
            message="Success.", data=uploaded_files, status_code=200
        )
