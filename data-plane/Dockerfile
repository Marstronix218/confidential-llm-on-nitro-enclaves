# Build context: the repo root (docker-compose.yml sets it)
# python:3.11.17-slim
FROM python@sha256:e88e9763f943ec1834f992a4b51e0f24500486803e8bc534e5767af9ea65f6ce

WORKDIR /app

COPY data-plane/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY data-plane/vsock_api_server.py data-plane/vsock_client.py common/utils.py ./

ENV PYTHONUNBUFFERED=1
EXPOSE 5000
CMD ["python", "vsock_api_server.py"]
