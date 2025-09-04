from rest_framework import serializers
from notifications.models import Notification
from user.serializers import ReturnUserSerializer


class NotificationSerializer(serializers.ModelSerializer):
    # user = ReturnUserSerializer(context={"is_testimony": True})
    class Meta:
        model = Notification
        fields = [
            'id',
            'redirect_url',
            'verb',
            'timestamp',
            'read',
            'message',
            'object_id',
        ]
        # read_only_fields = ['id', 'timestamp', 'read']

    '''def create(self, validated_data):
        return Notification.objects.create(**validated_data)'''
