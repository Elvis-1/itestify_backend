from rest_framework import serializers

from mobile_user_auth.serializers import ReturnUserSerializer
from testimonies.models import TextTestimony, VideoTestimony

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
        
    def create(self, validated_data):
        # Add the currently authenticated user to the validated data
        user = self.context['request'].user
        validated_data['uploaded_by'] = user
        return super().create(validated_data)
        

class ReturnVideoTestimonySerializer(serializers.ModelSerializer):
    
    uploaded_by = ReturnUserSerializer()
    
    class Meta:
        model = VideoTestimony
        fields = ["id", "title", "category","source", "upload_status", "video_file", "thumbnail", "rejection_reason", "uploaded_by", "created_at", "updated_at"]
        
             