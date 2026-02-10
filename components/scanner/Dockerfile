# components/scanner/Dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY scanner.py .

RUN useradd -m scanner && \
    mkdir -p /var/log/scanner && \
    chown -R scanner:scanner /app /var/log/scanner

USER scanner

CMD ["python", "scanner.py"]
