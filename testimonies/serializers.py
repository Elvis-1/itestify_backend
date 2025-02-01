from rest_framework import serializers

from user.serializers import ReturnUserSerializer
from .models import TextTestimony, VideoTestimony

class TextTestimonySerializer(serializers.ModelSerializer):
    class Meta:
        model = TextTestimony
        fields = ["title", "category", "content", "status", "rejection_reason", "uploaded_by"]
        

class ReturnTextTestimonySerializer(serializers.ModelSerializer):
    
    uploaded_by = ReturnUserSerializer()
    
    class Meta:
        model = TextTestimony
        fields = ["id", "title", "category", "content", "status", "rejection_reason", "uploaded_by", "created_at", "updated_at"]
        

class VideoTestimonySerializer(serializers.ModelSerializer):
    class Meta:
        model = VideoTestimony
        fields = ["title", "category", "source", "upload_status", "video_file", "thumbnail", "rejection_reason", "uploaded_by"]
        

class ReturnVideoTestimonySerializer(serializers.ModelSerializer):
    class Meta:
        model = VideoTestimony
        fields = ["id", "title", "category","source", "upload_status", "video_file", "thumbnail", "rejection_reason", "uploaded_by", "created_at", "updated_at"]
        
             