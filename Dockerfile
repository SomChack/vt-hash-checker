FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DB_PATH=/data/vt_history.sqlite3 \
    LOG_PATH=/logs/app.log \
    CACHE_TTL_DAYS=7 \
    REQUESTS_PER_HOUR=20

WORKDIR /srv/app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# Файлы приложения должны читаться непривилегированным пользователем,
# даже если на хосте у них узкие права (например, 600).
RUN chmod -R a+rX /srv/app

RUN useradd --system --uid 10001 --no-create-home appuser \
    && mkdir -p /data /logs \
    && chown -R appuser:appuser /data /logs

USER appuser

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
