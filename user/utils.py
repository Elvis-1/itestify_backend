import os
from django.utils.crypto import get_random_string
from django.core.mail import EmailMessage


class Util:
    @staticmethod
    def generate_entry_code():
        """ generate 4 digit entry code for user"""
        return get_random_string(length=4, allowed_chars='0123456789')