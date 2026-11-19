FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /srv

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY demo ./demo

RUN mkdir -p /srv/data && useradd --create-home --uid 10001 proxy \
    && chown -R proxy:proxy /srv
USER proxy

EXPOSE 8000 3128
CMD ["python", "-m", "app.main"]
