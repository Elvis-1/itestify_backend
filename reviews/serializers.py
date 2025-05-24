from rest_framework import serializers
from .models import Review
from user.models import User

class ReviewSerializer(serializers.ModelSerializer):
    user = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(),
        default=serializers.CurrentUserDefault(),
        required=False
    )
    user_email = serializers.SerializerMethodField(read_only=True)
    user_full_name = serializers.SerializerMethodField(read_only=True)
    
    class Meta:
        model = Review
        fields = ['id', 'user', 'user_email', 'user_full_name', 'rating', 'message', 'created_at']
        read_only_fields = ['id', 'created_at', 'user_email', 'user_full_name']
    
    def get_user_email(self, obj):
        return obj.user.email if obj.user else None
    
    def get_user_full_name(self, obj):
        return obj.user.full_name if obj.user else None

    def validate_rating(self, value):
        if value < 1 or value > 5:
            raise serializers.ValidationError("Rating must be between 1 and 5")
        return value

    def create(self, validated_data):
        if 'user' not in validated_data:
            validated_data['user'] = self.context['request'].user
        return super().create(validated_data)