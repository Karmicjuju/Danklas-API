# syntax=docker/dockerfile:1

# Builder stage
FROM python:3.13-slim as builder
WORKDIR /app

# Install Poetry and build dependencies
RUN pip install poetry
COPY pyproject.toml poetry.lock* ./
RUN poetry export -f requirements.txt --output requirements.txt --without-hashes
RUN pip install --prefix=/install -r requirements.txt

# Copy app code
COPY . .

# Final stage: Distroless
FROM gcr.io/distroless/python3-debian12
WORKDIR /app
COPY --from=builder /install /usr/local
COPY --from=builder /app /app
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"] 