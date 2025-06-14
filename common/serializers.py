from rest_framework import serializers


class SuccessResponseSerializer(serializers.Serializer):
    status = serializers.CharField(default="success")
    message = serializers.CharField()


class ErrorResponseSerializer(SuccessResponseSerializer):
    status = serializers.CharField(default="failed")
    err_code = serializers.CharField()


class ErrorDataResponseSerializer(ErrorResponseSerializer):
    data = serializers.DictField()


# serializer for file Upload
class MediaUploadSerializer(serializers.Serializer):
    files = serializers.ListField(child=serializers.FileField())
