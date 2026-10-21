#!/bin/bash
# One-time setup for a data-plane instance (Amazon Linux 2023, Nitro Enclaves enabled).
# Log out and back in afterwards so the ne/docker group membership takes effect.
# Then, from the repo root: python3.11 -m venv ~/venv, pip install the pinned requirements,
# python enclave/download_model.py, docker build -f enclave/Dockerfile -t llm-enclave . (see README).
set -euo pipefail

# Must be >= the --memory / --cpu-count that admin.py passes to `nitro-cli run-enclave` (8192 / 2)
ENCLAVE_MEMORY_MIB=${ENCLAVE_MEMORY_MIB:-8192}
ENCLAVE_CPU_COUNT=${ENCLAVE_CPU_COUNT:-2}

# python3.11: the pinned requirements need Python >= 3.10 (AL2023's default python3 is 3.9)
sudo dnf install -y aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel git python3.11 python3.11-pip

sudo usermod -aG ne "$USER"
sudo usermod -aG docker "$USER"

# Reserve memory and vCPUs for the enclave (the default is only 512 MiB)
ALLOCATOR_YAML=/etc/nitro_enclaves/allocator.yaml
sudo sed -r "s/^([[:space:]]*memory_mib[[:space:]]*:[[:space:]]*).*/\1${ENCLAVE_MEMORY_MIB}/" -i "$ALLOCATOR_YAML"
sudo sed -r "s/^([[:space:]]*cpu_count[[:space:]]*:[[:space:]]*).*/\1${ENCLAVE_CPU_COUNT}/" -i "$ALLOCATOR_YAML"

sudo systemctl enable --now nitro-enclaves-allocator.service
sudo systemctl restart nitro-enclaves-allocator.service
sudo systemctl enable --now docker
