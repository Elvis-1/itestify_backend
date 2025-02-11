from django.apps import AppConfig


class TestimoniesConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'testimonies'

    def ready(self):
        import testimonies.signals