FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY . /app

ENV PYTHONUNBUFFERED=1
EXPOSE 8080

# Ajusta si tu main.py expone app.run(host="0.0.0.0", port=8080)
CMD ["python", "main.py"]
