# from rest_framework import serializers
# from .models import Review
# from user.models import User

# class ReviewSerializer(serializers.ModelSerializer):
#     user = serializers.PrimaryKeyRelatedField(
#         queryset=User.objects.all(),
#         default=serializers.CurrentUserDefault(),
#         required=False  # Make user not required for admin updates
#     )
#     user_email = serializers.SerializerMethodField(read_only=True)
    
#     class Meta:
#         model = Review
#         fields = ['id', 'user', 'user_email', 'rating', 'message', 'created_at']
#         read_only_fields = ['id', 'created_at', 'user_email']
#         extra_kwargs = {
#             'rating': {
#                 'min_value': 1,
#                 'max_value': 5,
#                 'error_messages': {
#                     'min_value': 'Rating must be at least 1',
#                     'max_value': 'Rating cannot be more than 5'
#                 }
#             },
#             'message': {'required': False, 'allow_blank': True}
#         }
    
#     def get_user_email(self, obj):
#         return obj.user.email if obj.user else None

#     def create(self, validated_data):
#         # Ensure user is set to current user when creating
#         if 'user' not in validated_data:
#             validated_data['user'] = self.context['request'].user
#         return super().create(validated_data)



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
    
    class Meta:
        model = Review
        fields = ['id', 'user', 'user_email', 'rating', 'message', 'created_at']
        read_only_fields = ['id', 'created_at', 'user_email']
    
    def get_user_email(self, obj):
        return obj.user.email if obj.user else None

    def validate_rating(self, value):
        if value < 1 or value > 5:
            raise serializers.ValidationError("Rating must be between 1 and 5")
        return value

    def create(self, validated_data):
        if 'user' not in validated_data:
            validated_data['user'] = self.context['request'].user
        return super().create(validated_data)