FROM python:3.12-slim

# System libs required by opencv/yara/Pillow
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgl1 libglib2.0-0 libjpeg62-turbo zlib1g curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
# Use headless opencv in containers (no GUI libs)
RUN sed -i 's/opencv-python>/opencv-python-headless>/' requirements.txt \
    && pip install --no-cache-dir -r requirements.txt

COPY . .

ENV FLASK_DEBUG=0 IMG4N6_HOST=0.0.0.0
EXPOSE 5000

# gunicorn for production; app object is app:app
CMD ["gunicorn", "-w", "2", "--threads", "4", "-b", "0.0.0.0:5000", "app:app"]
