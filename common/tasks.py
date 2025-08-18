from celery import shared_task

import requests
from django.core.mail import EmailMessage
from .utils import load_email_template, interpolate_template
from django.conf import settings

@shared_task
def ping_server():
    base_url = "https://itestify-backend-1.onrender.com/common/health"

    requests.get(base_url)

    return "server pinged..."


@shared_task
def send_email(template_name, params, meta_data):
    """
    template_name: str (e.g., "welcome")
    params: dict -> keys used inside the template body/subject
    email_meta: dict -> contains "to_email", "from_email", etc.
    """
    try:
        template = load_email_template(template_name)
        subject = interpolate_template(template.get("subject", ""), params)
        body = interpolate_template(template.get("body", ""), params)

        email = EmailMessage(
            subject=subject,
            body=body,
            from_email="If not God Tech <{}>".format(settings.EMAIL_HOST_USER),
            to=[meta_data["email"]]
        )

        email.content_subtype = "html"  # <- Enable HTML content
        email.send()

    except Exception as e:  
        # Log or handle email failure
        raise e
