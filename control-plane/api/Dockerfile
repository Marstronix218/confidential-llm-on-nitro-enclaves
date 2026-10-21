# Build context: the repo root (docker-compose.yml sets it)
# python:3.11.17-slim
FROM python@sha256:e88e9763f943ec1834f992a4b51e0f24500486803e8bc534e5767af9ea65f6ce

WORKDIR /app

COPY control-plane/api/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY control-plane/api/ ./
COPY common/utils.py ./

# Run as an unprivileged user; /data is where docker-compose mounts KEY_DIRECTORY
RUN useradd --system --uid 10001 app && mkdir -p /data && chown app /data
USER app

ENV PYTHONUNBUFFERED=1
EXPOSE 8501
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8501/health', timeout=4)"
CMD ["python", "chat.py"]
