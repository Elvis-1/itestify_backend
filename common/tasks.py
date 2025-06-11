from celery import shared_task

import requests

@shared_task
def ping_server():
    base_url = "https://itestify-backend-1.onrender.com/common/health"

    response = requests.get(base_url)

    return "server pinged..."