from rest_framework.views import APIView
from rest_framework import viewsets
from rest_framework.permissions import AllowAny

from .serializers import PaymentSerializer, VerifyOTPSerializer, VerifyPinSerializer
from .flutterwave import FlutterWave

from common.responses import CustomResponse
from common.exceptions import handle_custom_exceptions
from common.error import ErrorCode

flutterwave = FlutterWave()

class PaymentAPIView(APIView):
    serializer_class = PaymentSerializer
    permission_classes = [AllowAny]

    @handle_custom_exceptions
    def post(self, request):
        # serializer = self.serializer_class(data=request.data)
        # serializer.is_valid(raise_exception=True)

        response = flutterwave.createCharge(request.data)

        if response.status != "success":
            return CustomResponse.error(
                message="Something went wrong initiating a payment, please try again.",
                err_code=ErrorCode.PAYMENT_ERROR,
                status_code=400
            )

        return CustomResponse.success(
            message="Payment initiated successfully.",
            data = response.data, # might return transaction receipt here
            status_code=200
        )



class UpdateChargeWithPINView(APIView):
    serializer_class = VerifyPinSerializer

    def put(self, request):
        serializer = self.serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        response = flutterwave.updatePIN(serializer.validated_data)

        return CustomResponse.success(
            message="Pin updated successfully.",
            data=response,
            status_code=200
        )


class UpdateChargeWithOTPView(APIView):
    serializer_class = VerifyOTPSerializer

    def put(self, request):
        serializer = self.serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        response = flutterwave.updatePIN(serializer.validated_data)

        return CustomResponse.success(
            message="Pin updated successfully.",
            data=response,
            status_code=200
        )



class TransactionAPIView(viewsets.ViewSet):
    # handle all transactions here.
    pass