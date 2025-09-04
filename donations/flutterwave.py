import os
import requests
import uuid

from common.utils import splitFullName
from common.exceptions import PaymentError

from .utils import AESEncryptor

FLUTTERWAVE_BASE_URL = "https://api.flutterwave.cloud/developersandbox"
# FLUTTERWAVE_BASE_URL = "https://api.flutterwave.com/v3"
FLUTTERWAVE_ACCESS_TOKEN = os.getenv("FLUTTERWAVE_ACCESS_TOKEN")
FLUTTERWAVE_ENCRYPTION_KEY = os.getenv("FLUTTERWAVE_ENCRYPTION_KEY")

encryptor = AESEncryptor(FLUTTERWAVE_ENCRYPTION_KEY)

class FlutterWave:
    def __init__(self):
        self.base_url = FLUTTERWAVE_BASE_URL
        return

    @property
    def headers(self):
        print(FLUTTERWAVE_ACCESS_TOKEN)
        return {
            'Authorization': f"Bearer ${FLUTTERWAVE_ACCESS_TOKEN}",
            # 'Authorization': "FLWSECK_TEST-1496f616286cace07e6f44399b5fc3fc-X",
            'Content-Type': "application/json",
            'X-Idempotency-Key': str(uuid.uuid4()),
            'X-Trace-Id': str(uuid.uuid4()),
            'X-Scenario-Key': 'scenario:auth_pin&issuer:approved'
        }

    def createCustomer(self, params):
        URL = self.base_url + "/customers"
        
        # split the full name into first name and last name
        first_name, last_name = splitFullName(params["full_name"])

        payload = {
            "name": {
                "first": first_name,
                "last": last_name
            },
            "email": params["email"]
        }
        
        response = requests.post(url=URL, json=payload, headers=self.headers)
        print(response.json())
        resp_data = response.json()
        
        if resp_data.get("status") != "success":
            raise PaymentError(f"Error creating customer: {resp_data["error"]["message"]}.")

        return resp_data


    def createCardPaymentMethod(self, params):
        URL = self.base_url + "/payment-method"

        card_details = {
            "encrypted_card_number": params["card_number"],
            "encrypted_cvv": params["CVV"],
            "encrypted_expiry_month": params["expiry_month"],
            "encrypted_expiry_year": params["expiry_year"],
        }

        # encrypt card details before passing the payload
        encrypted_card_details = encryptor.encrypt_dict(card_details)

        payload = {
            "type": "card",
            "card": encrypted_card_details
        }

        response = requests.post(url=URL, json=payload, headers=self.headers)

        resp_data = response.json()

        if resp_data.get("status") != "success":
            raise PaymentError(f"Error creating card payment method: {resp_data["error"]["message"]}.")

        return resp_data


    def createCharge(self, params):
        customer_id = self.createCustomer(params).data.id
        payment_method_id = self.createCardPaymentMethod(params).data.id
        URL = self.base_url + "/charges?type=card"

        payload = {
            "tx_ref": str(uuid.uuid4()),
            "customer_id": customer_id,
            "payment_method_id": payment_method_id,
            "amount": params["amount"],
            "currency": params["currency"],
            "redirect_url": params["redirect_url"] or "www.google.com",
            "meta": {
                "person_name": params["full_name"],
                "role": "Donator"
            }
        }

        response = requests.post(url=URL, json=payload, headers=self.headers)

        resp_data = response.json()

        if resp_data.get("status") != "success":
            raise PaymentError("Error initiating charge, please try again later.")

        return resp_data

    def updatePIN(self, params):
        URL = self.base_url + f"/charges/{params.charge_id}"
        pin_dict = {
            "encrypted_pin": params.pin
        }

        data = {
            "authorization": {
                "type": "pin",
                "pin": encryptor.encrypt_dict(pin_dict)
            }
        }

        response = requests.put(
            url=URL,
            json=data,
            headers=self.headers
        )

        resp_data = response.json()

        if response.status_code != 200 and resp_data.get("status") != "success":
            raise PaymentError("Error updating PIN, please try again later.")

        return resp_data

    def updateOTP(self, params):
        URL = self.base_url + f"/charges/{params.charge_id}"

        data = {
            "authorization": {
                "type": "otp",
                "otp": {
                    "code": params.otp_code
                }
            }
        }

        response = requests.put(
            url=URL,
            json=data,
            headers=self.headers
        )

        resp_data = response.json()

        if resp_data.get("status") != "success":
            raise PaymentError("Error updating PIN, please try again later.")

        return resp_data

    def verifyPayment(params):
        return