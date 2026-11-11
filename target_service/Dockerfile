FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir flask requests

COPY app.py .

ENV TARGET_PORT=80
EXPOSE 80

CMD ["python", "app.py"]
