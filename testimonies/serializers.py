from rest_framework import serializers

from user.serializers import ReturnUserSerializer
from .models import TextTestimony, VideoTestimony

class TextTestimonySerializer(serializers.ModelSerializer):
    class Meta:
        model = TextTestimony
        fields = ["title", "category", "content"]
        
    def create(self, validated_data):
        # Add the currently authenticated user to the validated data
        user = self.context['request'].user
        validated_data['uploaded_by'] = user
        return super().create(validated_data)

class ReturnTextTestimonySerializer(serializers.ModelSerializer):
    
    uploaded_by = ReturnUserSerializer()
    
    class Meta:
        model = TextTestimony
        fields = ["id", "title", "category", "content", "status", "rejection_reason", "uploaded_by", "created_at", "updated_at"]
        

class VideoTestimonySerializer(serializers.ModelSerializer):
    class Meta:
        model = VideoTestimony
        fields = ["title", "category", "source", "upload_status", "scheduled_datetime", "video_file", "thumbnail"]
        
    
    def validate(self, data):
        """Ensure scheduled_datetime is required when upload_status is 'schedule_for_later'."""
        upload_status = data.get("upload_status", self.instance.upload_status if self.instance else None)
        scheduled_datetime = data.get("scheduled_datetime", self.instance.scheduled_datetime if self.instance else None)

        if upload_status == VideoTestimony.UPLOAD_STATUS.SCHEDULE_LATER and not scheduled_datetime:
            raise serializers.ValidationError({"scheduled_datetime": "This field is required when upload_status is 'schedule_for_later'."})

        return data
        
    def create(self, validated_data):
        # Add the currently authenticated user to the validated data
        user = self.context['request'].user
        validated_data['uploaded_by'] = user
        return super().create(validated_data)
        

class ReturnVideoTestimonySerializer(serializers.ModelSerializer):
    
    uploaded_by = ReturnUserSerializer()
    
    class Meta:
        model = VideoTestimony
        fields = ["id", "title", "category","source", "upload_status", "video_file", "thumbnail", "rejection_reason", "scheduled_datetime", "uploaded_by", "created_at", "updated_at"]
             