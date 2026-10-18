# // Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# // SPDX-License-Identifier: MIT-0

#vsock demo image
# -----------------------------
# Nitro Enclaves LLM image (Qwen2.5-0.5B-Instruct by default; GPT-2 also supported)
# -----------------------------
    FROM public.ecr.aws/amazonlinux/amazonlinux:2023-minimal

    # Install Python and essential tools
    RUN dnf update -y \
        && dnf install python3.11 python3.11-pip iproute -y \
        && dnf clean all
    
    # Set working directory
    WORKDIR /app
    
    # Install minimal Python dependencies
    RUN python3.11 -m pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu \
        && python3.11 -m pip install --no-cache-dir 'transformers[torch]' \
        && python3.11 -m pip install --no-cache-dir PyCryptodome
    
    # Copy app code
    COPY vsock_server.py ./
    COPY traffic_forwarder.py ./
    COPY utils.py ./
    COPY run.sh ./
    
    # Copy the model downloaded by download_model.py (tokenizer + weights)
    COPY model ./model
    
    # Make run.sh executable
    RUN chmod +x /app/run.sh
    
    # Expose port
    EXPOSE 5000
    
    # Environment
    ENV PYTHONUNBUFFERED=1 \
        MODEL_DIR=/app/model
    
    # Entry point
    CMD ["/app/run.sh"]