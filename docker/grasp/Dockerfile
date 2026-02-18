# GRASP Engine - Multi-stage Production Build
# Stage 1: Build dependencies
FROM python:3.12-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Stage 2: Production image
FROM python:3.12-slim AS production

# Create non-root user
RUN groupadd -r grasp && useradd -r -g grasp -d /app -s /sbin/nologin grasp

# Copy installed dependencies from builder
COPY --from=builder /install /usr/local

# Application code
WORKDIR /app
COPY src/ ./src/

# Ownership
RUN chown -R grasp:grasp /app

USER grasp

ENV PYTHONPATH=/app/src \
    PYTHONUNBUFFERED=1

ENTRYPOINT ["uvicorn", "grasp.main:app", "--host", "0.0.0.0", "--port", "8443", "--reload", "--reload-dir", "/app/src"]
