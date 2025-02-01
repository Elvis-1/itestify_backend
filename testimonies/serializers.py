from rest_framework import serializers
from .models import TextTestimony

class TextTestimonySerializer(serializers.ModelSerializer):
    class Meta:
        model = TextTestimony
        fields = ["title", "category", "content", "rejection_reason", "uploaded_by"]
        

class ReturnTextTestimonySerializer(serializers.ModelSerializer):
    class Meta:
        model = TextTestimony
        fields = ["id", "title", "category", "content", "rejection_reason", "uploaded_by", "created_at", "updated_at"]
        
             