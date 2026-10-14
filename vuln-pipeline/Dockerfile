# Demo image: deliberately outdated and run as root so the scanners have findings.
FROM python:3.9-slim
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ app/
EXPOSE 8000
CMD ["python", "app/app.py"]
