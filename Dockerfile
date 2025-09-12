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

CMD ["daphne", "-b", "0.0.0.0", "-p", "8000", "-w", "4", "itestify_backend.asgi:application"]

