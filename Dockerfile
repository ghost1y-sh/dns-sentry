FROM python:3.12-slim

WORKDIR /app

# Install whois binary (needed by python-whois)
RUN apt-get update && \
    apt-get install -y --no-install-recommends whois && \
    rm -rf /var/lib/apt/lists/*

# Install dependencies first (cache layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app code
COPY . .

# Non-root user for security
RUN useradd -r -s /bin/false sentry && \
    chown -R sentry:sentry /app
USER sentry

EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "120", "app:create_app()"]