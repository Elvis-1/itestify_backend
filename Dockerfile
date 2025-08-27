# Dockerfile
FROM python:3.12.3-slim

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

WORKDIR /app

# Add required packages for building psycopg2
RUN apt-get update \
  && apt-get install -y build-essential libpq-dev gcc \
  && apt-get clean


COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY . .

#CMD ["gunicorn", "itestify_backend.wsgi:application", "--bind", "0.0.0.0:8000"]
CMD ["daphne", "-b", "0.0.0.0", "-p", "8000", "itestify_backend.asgi:application"]