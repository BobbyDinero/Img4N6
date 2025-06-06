# Image Threat Scanner - Docker Configuration
FROM python:3.10-slim-bullseye

# Set maintainer
LABEL maintainer="your-email@domain.com"
LABEL description="Image Threat Scanner - Advanced forensic analysis and steganography detection"
LABEL version="1.0.0"

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_APP=app.py \
    FLASK_ENV=production \
    FLASK_DEBUG=0

# Create app user for security
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    make \
    libssl-dev \
    libffi-dev \
    libgl1-mesa-glx \
    libglib2.0-0 \
    yara \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set work directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Install YARA Python bindings
RUN pip install --no-cache-dir yara-python

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p uploads temp_sessions logs static/css static/js static/images templates

# Set proper permissions
RUN chown -R appuser:appuser /app && \
    chmod +x run_app.bat

# Switch to non-root user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/ || exit 1

# Expose port
EXPOSE 5000

# Run the application
CMD ["python", "app.py"]