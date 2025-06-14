import random
import threading
import os
from django.template.loader import render_to_string
from django.core.mail import EmailMessage, EmailMultiAlternatives
from django.conf import settings
from user import models as account_model
from django.urls import reverse

# Email threading


class EmailThread(threading.Thread):
    def __init__(self, email):
        self.email = email
        threading.Thread.__init__(self)

    def run(self):
        self.email.send()


class EmailUtil:
    def send_password_reset_email(user):
        from_email = "If not God Tech <{}>".format(settings.EMAIL_HOST_USER)
        subject = 'Password Reset OTP'
        code = random.randint(1000, 9999)
        print(code)
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

        email_message = EmailMessage(subject=subject, body=message, to=[
                                     user.email], from_email=from_email)
        email_message.content_subtype = 'html'

        EmailThread(email_message).start()

    def send_verification_email(user):
        from_email = "If not God Tech <{}>".format(settings.EMAIL_HOST_USER)
        subject = 'Email Verification'
        code = random.randint(1000, 9999)
        print(code)
        message = f'Your email verification OTP is: <strong>{code}</strong>'

        otp = account_model.Otp.objects.get_or_none(user=user)

        if not otp:
            account_model.Otp.objects.create(user=user, code=code)
        else:
            otp.code = code
            otp.save()

        email_message = EmailMessage(
            subject=subject,
            body=message,
            to=[user.email],
            from_email=from_email
        )
        email_message.content_subtype = 'html'

        EmailThread(email_message).start()

    @staticmethod
    def send_email(data):
        email = EmailMessage(
            subject=data['email_subject'], from_email=os.environ.get('EMAIL_HOST_USER'), body=data['email_body'], to=[data['to_email']])
        email.send()

    @staticmethod
    def send_reset_password_email_link(user, reset_link):
        from_email = os.environ.get('EMAIL_HOST_USER')
        subject = 'Password Reset Request'

        # Create HTML email content directly
        message = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0;">
                <h2 style="color: #333;">Password Reset Request</h2>
                
                <p>Hello {user.full_name or 'there'},</p>
                
                <p>We received a request to reset your password. If you did not make this request, please ignore this email.</p>
                
                <p>To reset your password, please click the link below:</p>
                
                <p>

                    <a href="{reset_link}" style="color: #3498db;">

                        Reset Password
                    </a>
                </p>

                <p style="margin-top: 30px; font-size: 0.9em; color: #777;">
                    If you have any questions, feel free to contact our support team.
                </p>
                
                <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #eee;">
                    <p>Best regards,<br>The Team</p>
                </div>
            </div>
        </body>
        </html>
        """

        email_message = EmailMessage(
            subject=subject,
            body=message,
            to=[user.email],
            from_email=from_email
        )
        email_message.content_subtype = 'html'
        EmailThread(email_message).start()

    @staticmethod
    def send_invitation_email(request, user, invitation_token):
        from_email = "If not God Tech <{}>".format(settings.EMAIL_HOST_USER)
        subject = 'You have been invited to join our platform'
        
        invitation_url = request.build_absolute_uri(
            reverse('accept-invitation') + f'?token={invitation_token}'
        )
        
        # Create HTML email content directly

        message = f"""
        <html>
        <body>
            <h2>Welcome to Our Platform!</h2>
            <p>Hello {user.full_name or 'there'},</p>
            <p>You have been invited to join our platform. Click the link below to complete your registration:</p>
            <p><a href="{invitation_url}" style="background-color: #4CAF50; color: white; padding: 10px 20px; text-align: center; text-decoration: none; display: inline-block; border-radius: 5px;">
                Complete Registration
            </a></p>
            <p>This invitation link will expire in 7 days.</p>
            <p>If the button doesn't work, copy and paste this URL into your browser:</p>
            <p>{invitation_url}</p>
        </body>
        </html>
        """

        email_message = EmailMessage(
            subject=subject,
            body=message,
            to=[user.email],
            from_email=from_email
        )
        email_message.content_subtype = 'html'
        EmailThread(email_message).start()

