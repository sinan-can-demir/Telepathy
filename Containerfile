FROM python:3.12-slim

RUN groupadd --system app && useradd --system --gid app --home-dir /app app

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=app:app . .

RUN mkdir -p /app/staticfiles && chown app:app /app/staticfiles

USER app

ENV DJANGO_SETTINGS_MODULE=pc.settings

EXPOSE 8000

CMD ["sh", "-c", "python manage.py migrate --noinput && python manage.py collectstatic --noinput && gunicorn pc.wsgi:application --bind 127.0.0.1:8000 --workers 3"]
