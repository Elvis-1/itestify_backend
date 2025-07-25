import os
import cloudinary.uploader

from django.conf import settings
import json

MAX_FILE_SIZE = 50 * 1024 * 1024

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
    base_path = os.path.join(settings.BASE_DIR, 'common', 'templates/emails')
    file_path = os.path.join(base_path, f"{template_name}.json")
    
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Email template '{template_name}' not found.")
    
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

    
def interpolate_template(template: str, params: dict):
    for key, value in params.items():
        template = template.replace(f"{{{{ {key} }}}}", str(value))
    return template

