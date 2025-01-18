from rest_framework import serializers
from .models import TextTestimony

class TextTestimonySerializer(serializers.ModelSerializer):
    class Meta:
        model = TextTestimony
        fields = '__all__'