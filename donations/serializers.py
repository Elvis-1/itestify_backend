from rest_framework import serializers
from user.serializers import ReturnUserSerializer
from .models import Transaction




class PaymentSerializer(serializers.ModelSerializer):
    full_name = serializers.CharField()
    email = serializers.EmailField()
    amount = serializers.IntegerField()
    currency = serializers.CharField()
    payment_method = serializers.CharField()
    card_number = serializers.CharField()
    expiry_month = serializers.CharField()
    expiry_year = serializers.CharField()
    CVV = serializers.CharField()

    class Meta:
        model = Transaction

    def validate(self, obj):
        if obj.get("currency") not in ["NGN", "USD"]:
            raise serializers.ValidationError("Currency must be either 'NGN' or 'USD'")

        if obj.get("payment_method") not in ["BANK", "CARD", "TRANSFER"]:
            raise serializers.ValidationError("Currency must be either 'BANK', 'CARD' or 'TRANSFER'")

        return obj



class VerifyPinSerializer(serializers.Serializer):
    pin = serializers.CharField()
    charge_id = serializers.CharField()

class VerifyOTPSerializer(serializers.Serializer):
    otp_code = serializers.CharField()
    charge_id = serializers.CharField()

class TransactionSerializer(serializers.ModelSerializer):
    
    user = ReturnUserSerializer
    
    class Meta:
        model = Transaction
        fields = ["id", "user", "reference", "amount", "currency", "status", "description", "created_at"]

