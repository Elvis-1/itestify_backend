import os
import cloudinary.uploader

from django.conf import settings
from django.core.cache import cache
import json
from django.apps import apps

MAX_FILE_SIZE = 50 * 1024 * 1024


def get_roles(name=None):
    if name:
        cache_key = f"role_{name}"
        role = cache.get(cache_key)
        if role is None:
            role = apps.get_model("user", "Role").objects.filter(name=name).first()
            cache.set(cache_key, role, timeout=3600)  # Cache for 1 hour
        return role

    cache_key = "all_roles"
    roles = cache.get(cache_key)
    if roles is None:
        roles = list(
            apps.get_model("user", "Role").objects.values_list("name", flat=True)
        )
        cache.set(cache_key, roles, timeout=3600)  # Cache for 1 hour

    return roles


def upload_file(files):
    uploaded_files = []

    for file in files:
        # # determine file type and validate
        is_video = file.content_type.startswith("video/")

        resource_type = "video" if is_video else "image"

        upload_result = cloudinary.uploader.upload_large(
            file, folder="media", resource_type=resource_type, chunk_size=6000000
        )

        uploaded_files.append(
            {
                "url": upload_result["url"],
                "file_name": file.name,
                "type": resource_type,
            }
        )

    return uploaded_files


def load_email_template(template_name):
    base_path = os.path.join(settings.BASE_DIR, "common", "templates/emails")
    file_path = os.path.join(base_path, f"{template_name}.json")

    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Email template '{template_name}' not found.")

    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def interpolate_template(template: str, params: dict):
    for key, value in params.items():
        template = template.replace(f"{{{{ {key} }}}}", str(value))
    return template
