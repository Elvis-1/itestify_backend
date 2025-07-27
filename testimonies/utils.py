from common.utils import upload_file


def transform_testimony_files(video_data):
    uploaded_files = upload_file([video_data["video_file"], video_data["thumbnail"]])

    video_data["video_file"] = uploaded_files[0]["url"]
    video_data["thumbnail"] = uploaded_files[1]["url"]

    return video_data



