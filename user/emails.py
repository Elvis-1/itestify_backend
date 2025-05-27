import random, threading
import os

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
        
        email_message = EmailMessage(subject=subject, body=message, to=[user.email], from_email=from_email)
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
    def send_invitation_email(user, invitation_code):
        from_email = "If not God Tech <{}>".format(settings.EMAIL_HOST_USER)
        subject = 'You have been invited to join our platform'
        
        # Create HTML email content directly
        message = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0;">
                <h2 style="color: #333;">Welcome to Our Platform!</h2>
                
                <p>Hello {user.full_name or 'there'},</p>
                
                <p>You have been invited to join our platform. Here are your account details:</p>
                
                <div style="background: #f9f9f9; padding: 15px; margin: 15px 0; border-left: 4px solid #3498db;">
                    <p><strong>Email:</strong> {user.email}</p>
                    <p><strong>Invitation Code:</strong> 
                        <span style="font-size: 18px; font-weight: bold; color: #3498db;">
                            {invitation_code}
                        </span>
                    </p>
                </div>
                
                <p>This invitation code will expire in 7 days.</p>
                
                <p>Please use this code to complete your registration and set up your account password.</p>
                
                <p style="margin-top: 30px; font-size: 0.9em; color: #777;">
                    If you did not request this invitation, please ignore this email or contact support.
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
            
