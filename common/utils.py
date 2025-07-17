import os
import cloudinary.uploader

from .responses import CustomResponse
from .serializers import MediaUploadSerializer
from .error import ErrorCode

from rest_framework.views import APIView
from rest_framework.decorators import api_view

from django.utils.timezone import now
from datetime import datetime, timedelta
from testimonies.models import VideoTestimony

MAX_FILE_SIZE = 50 * 1024 * 1024


def upload_file(files):
    uploaded_files = []

    for file in files:
        # # determine file type and validate
        is_video = file.content_type.startswith("video/")
        is_image = file.content_type.startswith("image/")

        # if not (is_video or is_image):
        #     return CustomResponse.error(
        #         message=f"Invalid file type for {file.name}",
        #         err_code=ErrorCode.BAD_REQUEST,
        #         status_code=400,
        #     )

        # # check if the file size exceed the max file size
        # if file.size > MAX_FILE_SIZE:
        #     return CustomResponse.error(
        #         err_code=ErrorCode.INVALID_VALUE,
        #         message=f"The file {file.name} exceeds the file limit of 50MB.",
        #         status_code=400,
        #     )

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

    return uploaded_files
