# ===========================================================================
# Red Team Agent - Multi-stage Dockerfile
# ===========================================================================

# ---------------------------------------------------------------------------
# Stage 1: Builder - install dependencies
# ---------------------------------------------------------------------------
FROM python:3.11-slim AS builder

WORKDIR /build

# Install system dependencies required for building Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for Docker layer caching
COPY requirements.txt .

# Install Python dependencies into a virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir gunicorn

# ---------------------------------------------------------------------------
# Stage 2: Runtime - lean production image
# ---------------------------------------------------------------------------
FROM python:3.11-slim AS runtime

# Install only runtime system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r redteam && useradd -r -g redteam -d /app -s /sbin/nologin redteam

WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application code
COPY app/ ./app/
COPY run.py .
COPY migrations/ ./migrations/

# Create necessary directories
RUN mkdir -p data reports logs && \
    chown -R redteam:redteam /app

# Switch to non-root user
USER redteam

# Expose application port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:5000/health || exit 1

# Default command
CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:5000", "--timeout", "120", "run:app"]
