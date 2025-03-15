import random, threading

from django.template.loader import render_to_string
from django.core.mail import EmailMessage, EmailMultiAlternatives
from django.conf import settings
from user import models as account_model

# Email threading
class EmailThread(threading.Thread):
    def __init__(self, email):
        self.email = email
        threading.Thread.__init__(self)

    def run(self):
        self.email.send()


class Util:
    def send_password_reset_email(user):
        from_email = "If not God Tech <{}>".format(settings.EMAIL_HOST_USER)
        subject = 'Password Reset OTP'
        code = random.randint(1000, 9999)
        # message = render_to_string(
        #     'password_reset_email.html',
        #     {
        #         'full_name': user.full_name,
        #         'code': code
        #     }
        # )
        message = f'Use this OTP to reset your password\n{code}'

        otp = account_model.Otp.objects.get_or_none(user=user)

        if not otp:
            account_model.Otp.objects.create(user=user, code=code)
        else:
            otp.code = code
            otp.save()

        email_message = EmailMessage(subject=subject, body=message, to=[user.email], from_email=from_email)
        email_message.content_subtype = 'html'

        EmailThread(email_message).start()




            
            
            
            
