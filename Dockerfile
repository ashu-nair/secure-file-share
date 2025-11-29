FROM python:3.10-slim
WORKDIR /app
COPY . /app
RUN apt-get update && apt-get install -y clamav clamav-daemon && freshclam
RUN pip install --no-cache-dir -r requirements.txt
EXPOSE 5000
CMD ["python", "app.py"]
