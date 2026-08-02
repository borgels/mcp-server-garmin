FROM python:3.12-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
COPY pyproject.toml ./
RUN pip install --no-cache-dir . && useradd -m app
COPY app ./app
USER app
EXPOSE 3000
CMD ["python", "-m", "app.server"]
