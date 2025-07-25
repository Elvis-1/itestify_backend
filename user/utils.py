import os
from django.utils.crypto import get_random_string
from rest_framework import serializers


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
        if not token.startswith("ey"):
            raise ValueError("Incorrect token format, please check.")
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            return payload  # valid token
        except jwt.ExpiredSignatureError:
            raise ValueError("Your link has expired, please request another.") # token expired
        except jwt.InvalidTokenError:
            raise ValueError("Invalid link, please check.")  # token invalid

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


    @staticmethod
    def validate_password(password):
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        if not any(c.isupper() for c in password):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not any(c.islower() for c in password):
            raise ValueError("Password must contain at least one lowercase letter.")
        if not any(c.isdigit() for c in password):
            raise ValueError("Password must contain at least one number.")
        special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        if not any(c in special_chars for c in password):
            raise ValueError("Password must contain at least one special character.")
        return password