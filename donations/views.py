import uuid

from rest_framework.views import APIView
from rest_framework import viewsets
from rest_framework.permissions import AllowAny, IsAuthenticated
from django.utils.dateparse import parse_date
from django.db.models import Q

from .serializers import InitiatePaymentSerializer, TransactionSerializer
from .thirdParty.flutterwave_sdk import FlutterwaveSDKService
from .models import Donation
from user.models import User

from common.responses import CustomResponse
from common.exceptions import handle_custom_exceptions
from common.error import ErrorCode
from support.helpers import StandardResultsSetPagination

from django.db.models import Q
from django.utils.dateparse import parse_date


flw_sdk = FlutterwaveSDKService()


class PaymentAPIView(APIView):
    serializer_class = InitiatePaymentSerializer
    permission_classes = [AllowAny]

    @handle_custom_exceptions
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        data = serializer.validated_data
        user = request.user if request.user.is_authenticated else None
        
        # Use provided details or get from logged-in user
        full_name = data.get("full_name")
        email = data.get("email")
        
        if not full_name or not email:
            if not user or not user.is_authenticated:
                return CustomResponse.error(
                    message="Full name and email are required for guest users",
                    status_code=400
                )

            user_data = User.objects.get(id=user.id)

            full_name = full_name or user_data.full_name
            email = email or user_data.email

        # Check for existing pending donation with same details
        existing_donation = Donation.objects.filter(
            user=user,
            email=email,
            amount=data["amount"],
            currency=data["currency"],
            status__in=[Donation.STATUS_CHOICES.PENDING, Donation.STATUS_CHOICES.FAILED]
        ).first()
        
        if existing_donation:
            # Reuse existing donation
            donation = existing_donation
            donation.status = Donation.STATUS_CHOICES.PENDING
            donation.transaction_type = data["payment_method"]
            tx_ref = donation.tx_ref
        else:
            # Create new donation
            tx_ref = f"donation_{uuid.uuid4().hex}"
            donation = Donation.objects.create(
                user=user,
                full_name=full_name,
                email=email,
                amount=data["amount"],
                currency=data["currency"],
                transaction_type=data["payment_method"],
                tx_ref=tx_ref,
                status=Donation.STATUS_CHOICES.PENDING,
            )
        
        try:
            response = flw_sdk.create_payment(
                tx_ref=tx_ref,
                amount=float(data["amount"]),
                currency=data["currency"],
                email=email,
                customer_name=full_name,
                redirect_url=data.get("redirect_url"),
                title="Donation Payment",
                description="Donation payment"
            )

            donation.metadata = response
            donation.save()

            return CustomResponse.success(
                message="Payment initiated successfully",
                data={
                    "donation_id": donation.id,
                    "tx_ref": tx_ref,
                    "payment_method": data["payment_method"],
                    "currency": data["currency"],
                    "amount": data["amount"],
                    "response": response,
                },
                status_code=201,
            )

        except Exception as e:
            donation.status = Donation.STATUS_CHOICES.FAILED
            donation.save()
            return CustomResponse.error(
                err_code=ErrorCode.PAYMENT_ERROR,
                message=f"Payment initiation failed: {str(e)}", status_code=400
            )


class VerifyPaymentView(APIView):
    permission_classes = [AllowAny]

    @handle_custom_exceptions
    def post(self, request):
        tx_ref = request.data.get("tx_ref")
        if not tx_ref:
            return CustomResponse.error(
                message="Transaction reference is required", status_code=400
            )

        try:
            donation = Donation.objects.get(tx_ref=tx_ref)
            response = flw_sdk.verify_transaction(tx_ref)

            if response.get("status") == "success":
                donation.status = Donation.STATUS_CHOICES.SUCCESS
            else:
                donation.status = Donation.STATUS_CHOICES.FAILED

            # Update payment method from response
            payment_type = response.get("data", {}).get("payment_type")
            if payment_type == "card":
                donation.transaction_type = Donation.TRANSACTION_TYPE.CARD
            elif payment_type == "banktransfer":
                donation.transaction_type = Donation.TRANSACTION_TYPE.TRANSFER

            donation.metadata.update(response)
            donation.save()

            return CustomResponse.success(
                message="Payment verification completed",
                data={
                    "donation_id": donation.id,
                    "status": donation.status,
                    "verification_response": response,
                },
            )

        except Donation.DoesNotExist:
            return CustomResponse.error(
                message="Transaction not found", status_code=404
            )
        except Exception as e:
            return CustomResponse.error(
                message=f"Verification failed: {str(e)}", status_code=400
            )


class TransactionViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]
    pagination_class = StandardResultsSetPagination
    
    def get_permissions(self):
        if self.action in ["create", "update", "destroy"]:
            self.permission_classes = [IsAuthenticated]
        elif self.action in ["list", "retrieve"]:
            self.permission_classes = [IsAuthenticated]
        return super().get_permissions()

    @handle_custom_exceptions
    def list(self, request):
        """Get all donations for the authenticated user"""
        # user = request.user
        
        # Filter parameters
        status = request.query_params.get("status", "").upper()
        currency = request.query_params.get("currency", "").upper()
        transaction_type = request.query_params.get("transaction_type", "").upper()
        search = request.query_params.get("search", "").strip()
        from_date = request.query_params.get("from")
        to_date = request.query_params.get("to")
        min_amount = request.query_params.get("min_amount")
        max_amount = request.query_params.get("max_amount")
        
        # Base queryset
        queryset = Donation.objects.filter().order_by("-created_at")
        
        # Apply filters
        if status:
            queryset = queryset.filter(status=status)
        if currency:
            queryset = queryset.filter(currency=currency)
        if transaction_type:
            queryset = queryset.filter(transaction_type=transaction_type)

        if search:
            queryset = queryset.filter(
            Q(email__icontains=search)
            | Q(tx_ref__icontains=search)
            | Q(amount__icontains=search)
            | Q(full_name__icontains=search)
        )

         # Apply date filtering
        if from_date:
            parsed_from_date = parse_date(from_date)
            if parsed_from_date:
                queryset = queryset.filter(
                    created_at__date__gte=parsed_from_date
                )

        if to_date:
            parsed_to_date = parse_date(to_date)

            if parsed_to_date:
                # Set time to the end of the day for inclusivity
                queryset = queryset.filter(created_at__date__lte=parsed_to_date)
        
        # Apply amount filtering
        if min_amount:
            try:
                min_amount = float(min_amount)
                queryset = queryset.filter(amount__gte=min_amount)
            except (ValueError, TypeError):
                pass
        if max_amount:
            try:
                max_amount = float(max_amount)
                queryset = queryset.filter(amount__lte=max_amount)
            except (ValueError, TypeError):
                pass
        
        # Pagination
        paginator = self.pagination_class()
        paginated_queryset = paginator.paginate_queryset(queryset, request)
        serializer = TransactionSerializer(paginated_queryset, many=True)
        return paginator.get_paginated_response(serializer.data)

    @handle_custom_exceptions
    def retrieve(self, request, pk=None):
        """Get a specific donation by ID"""
        try:
            donation = Donation.objects.get(id=pk, user=request.user)
        except Donation.DoesNotExist:
            return CustomResponse.error(
                message="Transaction not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404
            )
        
        serializer = TransactionSerializer(donation)
        return CustomResponse.success(
            message="Transaction retrieved successfully",
            data=serializer.data,
            status_code=200
        )

    @handle_custom_exceptions
    def update(self, request, pk=None):
        """Update donation description only"""
        try:
            donation = Donation.objects.get(id=pk, user=request.user)
        except Donation.DoesNotExist:
            return CustomResponse.error(
                message="Transaction not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404
            )
        
        # Only allow updating description
        description = request.data.get("description")
        if description is not None:
            donation.description = description
            donation.save()
        
        serializer = TransactionSerializer(donation)
        return CustomResponse.success(
            message="Transaction updated successfully",
            data=serializer.data,
            status_code=200
        )

    @handle_custom_exceptions
    def destroy(self, request, pk=None):
        """Delete a donation (only if PENDING or FAILED)"""
        try:
            donation = Donation.objects.get(id=pk, user=request.user)
        except Donation.DoesNotExist:
            return CustomResponse.error(
                message="Transaction not found",
                err_code=ErrorCode.NOT_FOUND,
                status_code=404
            )
        
        # Only allow deletion of PENDING or FAILED transactions
        if donation.status not in [Donation.STATUS_CHOICES.PENDING, Donation.STATUS_CHOICES.FAILED]:
            return CustomResponse.error(
                message="Cannot delete successful transactions",
                err_code=ErrorCode.FORBIDDEN,
                status_code=403
            )
        
        donation.delete()
        return CustomResponse.success(
            message="Transaction deleted successfully",
            status_code=200
        )


class DonationStatsView(APIView):
    permission_classes = [IsAuthenticated]
    
    @handle_custom_exceptions
    def get(self, request):
        """Get donation statistics"""
        successful_donations = Donation.objects.filter(status=Donation.STATUS_CHOICES.SUCCESS)
        
        total_successful_transactions = successful_donations.count()
        unique_donors = successful_donations.values('email').distinct().count()
        
        return CustomResponse.success(
            message="Donation stats retrieved successfully",
            data={
                "total_successful_donations": total_successful_transactions,
                "unique_donors": unique_donors
            },
            status_code=200
        )
