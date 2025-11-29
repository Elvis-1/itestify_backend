from rest_framework import serializers
from user.serializers import ReturnUserSerializer
from .models import Donation
from decimal import Decimal


class InitiatePaymentSerializer(serializers.Serializer):
    full_name = serializers.CharField(max_length=255, required=False)
    email = serializers.EmailField(required=False)
    amount = serializers.DecimalField(max_digits=12, decimal_places=2, min_value=Decimal('0.01'))
    currency = serializers.ChoiceField(choices=["NGN", "USD"])
    payment_method = serializers.ChoiceField(choices=["BANK", "CARD", "TRANSFER"])
    redirect_url = serializers.URLField(required=False)


class VerifyPinSerializer(serializers.Serializer):
    pin = serializers.CharField()
    charge_id = serializers.CharField()


class VerifyOTPSerializer(serializers.Serializer):
    otp_code = serializers.CharField()
    charge_id = serializers.CharField()


class TransactionSerializer(serializers.ModelSerializer):
    # user = ReturnUserSerializer()

    class Meta:
        model = Donation
        fields = [
            "id",
            "full_name",
            "email",
            "tx_ref",
            "amount",
            "currency",
            "transaction_type",
            "status",
            "created_at",
        ]
    
    def to_representation(self, instance):
        data = super().to_representation(instance)
        data['amount'] = float(data['amount'])
        return data


class DonationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Donation
        fields = [
            "full_name",
            "email",
            "amount",
            "currency",
            "transaction_type",
        ]
