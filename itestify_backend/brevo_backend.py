from django.core.mail.backends.base import BaseEmailBackend
import sib_api_v3_sdk
from sib_api_v3_sdk.rest import ApiException
from django.conf import settings


class BrevoEmailBackend(BaseEmailBackend):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        configuration = sib_api_v3_sdk.Configuration()
        configuration.api_key['api-key'] = settings.BREVO_API_KEY
        self.api_instance = sib_api_v3_sdk.TransactionalEmailsApi(
            sib_api_v3_sdk.ApiClient(configuration)
        )

    def send_messages(self, email_messages):
        """
        email_messages is a list of django.core.mail.EmailMessage
        """
        num_sent = 0
        for message in email_messages:
            try:
                
                body_text = message.body or "text content"

                html_content = None

                # Handle html_message (Django stores it in message.alternatives)
                if hasattr(message, "alternatives"):
                    for alt_body, mime_type in message.alternatives:
                        if mime_type == "text/html":
                            html_content = alt_body
                            break

                send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(
                    to=[{"email": addr} for addr in message.to],
                    sender={"name": "IfnotGod Tech", "email": settings.DEFAULT_FROM_EMAIL},
                    subject=message.subject,
                    html_content=html_content,
                    text_content=body_text,
                )
                self.api_instance.send_transac_email(send_smtp_email)
                num_sent += 1
            except ApiException as e:
                print(f"Brevo API Exception: {e}")
                if not self.fail_silently:
                    raise
        return num_sent
