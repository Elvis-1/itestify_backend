from rest_framework import serializers
from user.serializers import ReturnUserSerializer
from .models import TransactionHistory



class TransactionHistorySerializer(serializers.ModelSerializer):
    
    user = ReturnUserSerializer
    
    class Meta:
        model = TransactionHistory
        fields = ["id", "user", "reference", "amount", "currency", "status", "description", "created_at"]

