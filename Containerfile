FROM python:3.12-slim

RUN groupadd --system app && useradd --system --gid app --home-dir /app app

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=app:app . .

RUN mkdir -p /app/staticfiles && chown app:app /app/staticfiles
# pc/settings.py's LOGGING writes to BASE_DIR/chat_debug.log; that file
# doesn't exist in the image (it's gitignored, created at runtime), and the
# app user can't create it because WORKDIR made /app root-owned before the
# chowned COPY above only touched the files inside it, not the directory
# itself.
RUN touch /app/chat_debug.log && chown app:app /app/chat_debug.log

USER app

ENV DJANGO_SETTINGS_MODULE=pc.settings

EXPOSE 8000

CMD ["sh", "-c", "python manage.py migrate --noinput && python manage.py collectstatic --noinput && gunicorn pc.wsgi:application --bind 127.0.0.1:8000 --workers 3"]
