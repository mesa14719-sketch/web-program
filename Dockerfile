FROM python:3.11-slim

# ثبّت PHP + المكتبات المطلوبة
RUN apt-get update && apt-get install -y \
    php-cli \
    php-curl \
    php-json \
    php-mbstring \
    php-xml \
    php-zip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ثبّت Python packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# انسخ باقي الملفات
COPY . .

# منفذ Render
EXPOSE 8000

CMD uvicorn server:app --host 0.0.0.0 --port $PORT
