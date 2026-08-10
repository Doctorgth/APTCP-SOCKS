FROM python:3.11-slim

WORKDIR /app
ENV PYTHONPATH=/app

# Сначала копируем только requirements.txt для кэширования слоя зависимостей
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Копируем весь исходный код проекта
COPY . /app/

# Пробрасываем порт по умолчанию
EXPOSE 1080

# Запускаем сервер с конфигом по умолчанию
CMD ["python", "server/main.py", "server/config.json"]