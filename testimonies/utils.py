import re
from collections import defaultdict

from common.utils import upload_file

def extract_video_testimonies(data, files):
    grouped = defaultdict(dict)
    pattern = re.compile(r'video_testimonies\[(\d+)]\[(\w+)]')

    for key, value in list(data.items()) + list(files.items()):
        match = pattern.match(key)
        if match:
            idx, field = match.groups()
            grouped[int(idx)][field] = value

    return [grouped[i] for i in sorted(grouped)]


def transform_testimony_files(video_data):
    uploaded_files = upload_file([video_data["video_file"], video_data["thumbnail"]])


    video_data["video_file"] = uploaded_files[0]["url"]
    video_data["thumbnail"] = uploaded_files[1]["url"]

    return video_data

