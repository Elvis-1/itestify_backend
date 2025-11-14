import os
import requests
import uuid
from typing import Dict, Any

class FlutterwaveSDKService:
    def __init__(self):
        self.secret_key = os.getenv("FLUTTERWAVE_SECRET_KEY")
        self.public_key = os.getenv("FLUTTERWAVE_PUBLIC_KEY")
        self.base_url = "https://api.flutterwave.com/v3"
        self.encryption_key = os.getenv("FLUTTERWAVE_ENCRYPTION_KEY")
    
    @property
    def headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.secret_key}",
            "Content-Type": "application/json"
        }
    
    def generate_tx_ref(self) -> str:
        """Generate unique transaction reference"""
        return f"flw_tx_ref_{uuid.uuid4().hex[:12]}"
    
    def test_api_key(self) -> Dict[str, Any]:
        """Test if API key is valid"""
        url = f"{self.base_url}/transactions"
        try:
            response = requests.get(url, headers=self.headers)
            return {"status": "success" if response.status_code != 401 else "error", "code": response.status_code}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    def create_payment(self, **kwargs) -> Dict[str, Any]:
        """Create payment using Flutterwave Standard"""
        if not self.secret_key:
            return {"status": "error", "message": "Flutterwave secret key not configured"}
            
        url = f"{self.base_url}/payments"
        
        payload = {
            "tx_ref": kwargs.get('tx_ref', self.generate_tx_ref()),
            "amount": str(kwargs['amount']),
            "currency": kwargs['currency'],
            "redirect_url": kwargs.get('redirect_url', 'https://your-app.com/callback'),
            "payment_options": "card,banktransfer,ussd,mobilemoney",
            "customer": {
                "email": kwargs['email'],
                "phonenumber": kwargs.get('phone', '08012345678'),
                "name": kwargs['customer_name']
            },
            "customizations": {
                "title": kwargs.get('title', 'Payment'),
                "description": kwargs.get('description', 'Payment for services'),
                "logo": kwargs.get('logo', '')
            }
        }
        
        try:
            response = requests.post(url, json=payload, headers=self.headers)
        
            if response.status_code == 401:
                return {"status": "error", "message": "Invalid Flutterwave API key"}
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"status": "error", "message": f"Request failed: {str(e)}"}
    
    def verify_transaction(self, tx_ref: str) -> Dict[str, Any]:
        """Verify transaction status using tx_ref"""
        if not self.secret_key:
            return {"status": "error", "message": "Flutterwave secret key not configured"}
        
        url = f"{self.base_url}/transactions/verify_by_reference"
        params = {"tx_ref": tx_ref}
        
        try:
            response = requests.get(url, headers=self.headers, params=params)
            if response.status_code == 401:
                return {"status": "error", "message": "Invalid API key"}
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            return {"status": "error", "message": f"Request failed: {str(e)}"}
    
    def charge_card(self, amount, currency, email, firstname, lastname, ip, card_details):
        """Initiate card payment"""
        return self.create_payment(
            amount=amount,
            currency=currency,
            email=email,
            customer_name=f"{firstname} {lastname}",
            title="Donation Payment",
            description="Donation payment"
        )
    
    def charge_bank_transfer(self, amount, currency, email, firstname, lastname, redirect_url=None):
        """Initiate bank transfer payment"""
        return self.create_payment(
            amount=amount,
            currency=currency,
            email=email,
            customer_name=f"{firstname} {lastname}",
            redirect_url=redirect_url,
            title="Donation Payment",
            description="Donation via bank transfer"
        )