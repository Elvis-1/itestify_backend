import os
from django.utils.crypto import get_random_string

import random
import string
import jwt
import datetime
SECRET_KEY = os.getenv("SECRET_KEY")


class Util:
    @staticmethod
    def generate_entry_code():
        """ generate 4 digit entry code for user"""
        return get_random_string(length=4, allowed_chars='0123456789')

    @staticmethod
    def generate_token(data, expiry_minutes=10):
        payload = {
            **data,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=expiry_minutes),
            "iat": datetime.datetime.utcnow(),
        }

        token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

        return token

    @staticmethod
    def verify_token(token):
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            return payload  # valid token
        except jwt.ExpiredSignatureError:
            return None # token expired
        except jwt.InvalidTokenError:
            return None  # token invalid

    @staticmethod
    def generate_password(length=12):
        if length < 8:
            raise ValueError("Password length must be at least 8 characters")

        special_chars = "!@#$%^&*()-_=+[]{}|;:,.<>?/"
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits

        # Ensure required characters are present
        password = [
            random.choice(uppercase),
            random.choice(special_chars),
            random.choice(digits),
            random.choice(lowercase),
        ]

        # Fill the rest of the password
        all_chars = special_chars + lowercase + uppercase + digits
        remaining = length - len(password)
        password += random.choices(all_chars, k=remaining)

        # Shuffle to avoid predictable pattern
        random.shuffle(password)

        return ''.join(password)