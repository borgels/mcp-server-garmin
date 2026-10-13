FROM python:3.12-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
# Dependencies are pinned to exact versions with hashes (see requirements.lock).
COPY requirements.lock ./
RUN pip install --no-cache-dir --require-hashes -r requirements.lock && useradd -m app
COPY pyproject.toml ./
COPY app ./app
USER app
EXPOSE 3000
CMD ["python", "-m", "app.server"]
