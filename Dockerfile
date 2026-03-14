FROM python:3.11-slim AS runner

WORKDIR /app

# Install dependencies first (layer caching)
COPY tools/requirements.txt ./tools/requirements.txt
RUN pip install --no-cache-dir -r tools/requirements.txt

# Copy application code
COPY tools/ ./tools/

EXPOSE 5001

CMD ["python", "tools/cisco_eox_webapp.py"]
