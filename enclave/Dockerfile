# // Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# // SPDX-License-Identifier: MIT-0

# -----------------------------
# Nitro Enclaves LLM image (Qwen2.5-0.5B-Instruct by default; GPT-2 also supported)
# Build from the repo root (the context must include common/):
#   docker build -f enclave/Dockerfile -t llm-enclave .
#   nitro-cli build-enclave --docker-uri llm-enclave:latest --output-file enclave/llm.eif
# Everything is pinned (base image digest, hash-locked Python packages, no `dnf update`) so that the
# same commit and model produce the same image, and so the same PCR0.
# -----------------------------
# public.ecr.aws/amazonlinux/amazonlinux:2023.12.20261016.0-minimal
FROM public.ecr.aws/amazonlinux/amazonlinux@sha256:db31805b873599314c8b7cf394ccf8ba798c07361f0d773fdeb8efb48a02ecac

# Python and `ip` (run.sh). AL2023 repositories are locked to the image's release version.
RUN dnf install -y python3.11 python3.11-pip iproute \
    && dnf clean all

WORKDIR /app

# Full lock with hashes (generated from enclave/requirements.in, see that file): every transitive
# dependency is pinned, and pip refuses any file whose hash differs.
COPY enclave/requirements.txt ./
RUN python3.11 -m pip install --no-cache-dir --require-hashes -r requirements.txt

# App code
COPY enclave/vsock_server.py enclave/traffic_forwarder.py enclave/nsm.py enclave/run.sh common/utils.py ./

# The model downloaded by `python enclave/download_model.py` (tokenizer + weights in enclave/model)
COPY enclave/model ./model

RUN chmod +x /app/run.sh

EXPOSE 5000

ENV PYTHONUNBUFFERED=1 \
    MODEL_DIR=/app/model

CMD ["/app/run.sh"]
