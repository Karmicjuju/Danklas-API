# syntax=docker/dockerfile:1

# Builder stage
FROM python:3.13-slim as builder
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Copy app code
COPY app/ ./app/

# Final stage: Distroless
FROM gcr.io/distroless/python3-debian12:debug-nonroot
WORKDIR /app

# Copy installed packages and app code
COPY --from=builder /install /usr/local
COPY --from=builder /app ./

# Expose port
EXPOSE 8000

# Run the application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]