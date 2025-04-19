FROM python:3.9-slim as builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libpq-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/venv
ENV VIRTUAL_ENV=/opt/venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"
COPY requirements.txt .
RUN python -m venv . && \
    pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

FROM python:3.9-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/venv /opt/venv

WORKDIR /app/server

COPY manage.py /app/
COPY server/ /app/server/

ENV VIRTUAL_ENV=/opt/venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

RUN mkdir -p /app/server/data

EXPOSE 8000

ENV DATABASE_URL=""
ENV SECRET_KEY=""

CMD ["uvicorn", "server.main:app", "--host", "0.0.0.0", "--port", "8000"]
