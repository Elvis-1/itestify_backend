from rest_framework import serializers

from user.serializers import ReturnUserSerializer
from .models import (
    UPLOAD_STATUS,
    InspirationalPictures,
    TextTestimony,
    VideoTestimony,
    TestimonySettings,
)

from datetime import datetime, timezone
from django.utils.timezone import now, timedelta
from django.conf import settings


class TestimonySettingsSerializer(serializers.ModelSerializer):
    class Meta:
        model = TestimonySettings
        fields = [
            "notify_admin",
        ]


class TextTestimonySerializer(serializers.ModelSerializer):
    class Meta:
        model = TextTestimony
        fields = ["id", "title", "category", "content"]

    def create(self, validated_data):
        # Add the currently authenticated user to the validated data
        user = self.context["request"].user
        validated_data["uploaded_by"] = user
        return super().create(validated_data)


class ReturnTextTestimonySerializer(serializers.ModelSerializer):

    uploaded_by = ReturnUserSerializer(context={"is_testimony": True})

    class Meta:
        model = TextTestimony
        fields = [
            "id",
            "title",
            "category",
            "content",
            "status",
            "rejection_reason",
            "uploaded_by",
            "created_at",
            "updated_at",
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        user = self.context.get("user")

        # conditionally remove 'uploaded_by' field based on user's role
        if user and user["role"] == "viewer":
            self.fields.pop("uploaded_by", None)


class VideoTestimonySerializer(serializers.ModelSerializer):
    class Meta:
        model = VideoTestimony
        fields = [
            "title",
            "category",
            "source",
            "upload_status",
            "scheduled_datetime",
            "video_file",
            "thumbnail",
        ]

    def validate(self, data):
        """Ensure scheduled_datetime is required when upload_status is 'scheduled'."""
        upload_status = data.get(
            "upload_status", self.instance.upload_status if self.instance else None
        )
        
        scheduled_datetime = data.get(
            "scheduled_datetime",
            self.instance.scheduled_datetime if self.instance else None,
        )
        
        current_datetime = now() + timedelta(hours=1) if settings.DEBUG == True else now()

        if scheduled_datetime < current_datetime:
            raise serializers.ValidationError(
                {
                    "scheduled_datetime": "You cannot schedule testimony for a past time."
                }
            )

        if upload_status == UPLOAD_STATUS.SCHEDULE_LATER and not scheduled_datetime:
            raise serializers.ValidationError(
                {
                    "scheduled_datetime": "This field is required when upload_status is 'scheduled'."
                }
            )

        return data

    def create(self, validated_data):
        # Add the currently authenticated user to the validated data
        user = self.context["request"].user
        validated_data["uploaded_by"] = user
        return super().create(validated_data)

class ReturnVideoTestimonySerializer(serializers.ModelSerializer):

    uploaded_by = ReturnUserSerializer(context={"is_testimony": True})

    class Meta:
        model = VideoTestimony
        fields = [
            "id",
            "title",
            "category",
            "source",
            "upload_status",
            "video_file",
            "thumbnail",
            "rejection_reason",
            "scheduled_datetime",
            "uploaded_by",
            "created_at",
            "updated_at",
        ]

    def get_video_file(self, obj):
        request = self.context.get("request")
        if request is not None:
            return request.build_absolute_uri(obj.video_file.url)
        return obj.video_file.url

    def get_thumbnail(self, obj):
        request = self.context.get("request")
        if request is not None:
            return request.build_absolute_uri(obj.thumbnail.url)
        return obj.thumbnail.url

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        request = self.context.get("request")
        user = request.user_data

        # conditionally remove 'uploaded_by' field based on user's role
        if user and user["role"] == "viewer":
            self.fields.pop("uploaded_by", None)

class InspirationalPicturesSerializer(serializers.ModelSerializer):
    class Meta:
        model = InspirationalPictures
        fields = ["thumbnail", "status", "downloads_count", "scheduled_datetime"]

    def validate(self, data):
        """Ensure scheduled_datetime is required when upload_status is 'scheduled'."""
        status = data.get("status", self.instance.status if self.instance else None)
        scheduled_datetime = data.get(
            "scheduled_datetime",
            self.instance.scheduled_datetime if self.instance else None,
        )

        if status == UPLOAD_STATUS.SCHEDULE_LATER and not scheduled_datetime:
            raise serializers.ValidationError(
                {
                    "scheduled_datetime": "This field is required when upload_status is 'scheduled'."
                }
            )

        return data

    def create(self, validated_data):
        # Add the currently authenticated user to the validated data
        user = self.context["request"].user
        validated_data["uploaded_by"] = user
        return super().create(validated_data)

class ReturnInspirationalPicturesSerializer(serializers.ModelSerializer):
    class Meta:
        model = InspirationalPictures
        fields = [
            "id",
            "thumbnail",
            "status",
            "downloads_count",
            "uploaded_by",
            "scheduled_datetime",
            "created_at",
            "updated_at",
        ]

    def get_thumbnail(self, obj):
        request = self.context.get("request")
        if request is not None:
            return request.build_absolute_uri(obj.thumbnail.url)
        return obj.thumbnail.url
