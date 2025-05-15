import os
from django.utils.crypto import get_random_string
from django.core.mail import EmailMessage


class Util:
    @staticmethod
    def send_email(data):

        email = EmailMessage(
            subject=data['email_subject'], from_email=os.environ.get('EMAIL_HOST_USER'), body=data['email_body'], to=[data['to_email']])
        email.send()

    @staticmethod
    def generate_entry_code():
        """ generate 4 digit entry code for user"""
        return get_random_string(length=4, allowed_chars='0123456789')
