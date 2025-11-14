import json
import os
import logging
from abc import ABC, abstractmethod

from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny

from .models import Donation

logger = logging.getLogger(__name__)


class BaseWebhookHandler(ABC):
    """Base class for payment webhook handlers"""
    
    @abstractmethod
    def verify_signature(self, request):
        """Verify webhook signature"""
        pass
    
    @abstractmethod
    def parse_payload(self, request):
        """Parse webhook payload"""
        pass
    
    @abstractmethod
    def get_transaction_reference(self, payload):
        """Extract transaction reference from payload"""
        pass
    
    @abstractmethod
    def process_event(self, payload, donation):
        """Process webhook event"""
        pass


class FlutterwaveWebhookHandler(BaseWebhookHandler):
    """Flutterwave webhook handler"""
    
    def verify_signature(self, request):
        signature = request.headers.get('verif-hash')
        secret_hash = os.getenv('FLUTTERWAVE_SECRET_HASH')
        return signature == secret_hash if secret_hash else False
    
    def parse_payload(self, request):
        return json.loads(request.body)
    
    def get_transaction_reference(self, payload):
        return payload.get('data', {}).get('tx_ref')
    
    def process_event(self, payload, donation):
        event = payload.get('event')  # Flutterwave uses 'event' not 'type'
        data = payload.get('data', {})
        
        if event == 'charge.completed' and data.get('status') == 'successful':
            donation.status = Donation.STATUS_CHOICES.SUCCESS
        elif event in ['charge.failed', 'charge.cancelled']:
            donation.status = Donation.STATUS_CHOICES.FAILED
        
        # Update payment method from webhook data
        payment_type = data.get('payment_type')
        if payment_type == 'card':
            donation.transaction_type = Donation.TRANSACTION_TYPE.CARD
        elif payment_type == 'banktransfer':
            donation.transaction_type = Donation.TRANSACTION_TYPE.TRANSFER
        
        donation.metadata.update(data)
        donation.save()
        return True


class PaystackWebhookHandler(BaseWebhookHandler):
    """Paystack webhook handler"""
    
    def verify_signature(self, request):
        signature = request.headers.get('x-paystack-signature')
        secret_key = os.getenv('PAYSTACK_SECRET_KEY')
        # Add proper signature verification logic here
        return True  # Simplified for now
    
    def parse_payload(self, request):
        return json.loads(request.body)
    
    def get_transaction_reference(self, payload):
        return payload.get('data', {}).get('reference')
    
    def process_event(self, payload, donation):
        event = payload.get('event')
        data = payload.get('data', {})
        
        if event == 'charge.success':
            donation.status = Donation.STATUS_CHOICES.SUCCESS
        elif event in ['charge.failed', 'charge.cancelled']:
            donation.status = Donation.STATUS_CHOICES.FAILED
        
        donation.metadata.update(data)
        donation.save()
        return True


@method_decorator(csrf_exempt, name='dispatch')
class GeneralWebhookView(APIView):
    """General webhook view that handles multiple payment providers"""
    permission_classes = [AllowAny]
    
    HANDLERS = {
        'flutterwave': FlutterwaveWebhookHandler(),
        'paystack': PaystackWebhookHandler(),
    }
    
    def post(self, request, provider):
        handler = self.HANDLERS.get(provider)
        if not handler:
            logger.warning(f"Unknown webhook provider: {provider}")
            return HttpResponse(status=404)
        
        try:
            # Verify signature
            if not handler.verify_signature(request):
                logger.warning(f"Invalid webhook signature for {provider}")
                return HttpResponse(status=401)
            
            # Parse payload
            payload = handler.parse_payload(request)
            tx_ref = handler.get_transaction_reference(payload)
            
            logger.info(f"Webhook received from {provider} for tx_ref: {tx_ref}")
            
            if not tx_ref:
                return HttpResponse(status=200)
            
            # Find donation
            try:
                donation = Donation.objects.get(tx_ref=tx_ref)
            except Donation.DoesNotExist:
                logger.warning(f"Donation not found for tx_ref: {tx_ref}")
                return HttpResponse(status=200)
            
            # Process event
            handler.process_event(payload, donation)
            logger.info(f"Webhook processed successfully for donation {donation.id}")
            
            return HttpResponse(status=200)
            
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON in {provider} webhook payload")
            return HttpResponse(status=400)
        except Exception as e:
            logger.error(f"Webhook processing error for {provider}: {str(e)}")
            return HttpResponse(status=500)


# Keep the old FlutterwaveWebhookView for backward compatibility
@method_decorator(csrf_exempt, name='dispatch')
class FlutterwaveWebhookView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        handler = FlutterwaveWebhookHandler()
        
        if not handler.verify_signature(request):
            logger.warning("Invalid Flutterwave webhook signature")
            return HttpResponse(status=401)
        
        try:
            payload = handler.parse_payload(request)
            tx_ref = handler.get_transaction_reference(payload)
            
            if not tx_ref:
                return HttpResponse(status=200)
            
            try:
                donation = Donation.objects.get(tx_ref=tx_ref)
            except Donation.DoesNotExist:
                logger.warning(f"Donation not found for tx_ref: {tx_ref}")
                return HttpResponse(status=200)
            
            handler.process_event(payload, donation)
            return HttpResponse(status=200)
            
        except Exception as e:
            logger.error(f"Flutterwave webhook error: {str(e)}")
            return HttpResponse(status=500)