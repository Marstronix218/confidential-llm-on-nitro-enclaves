# AWS setup guide

This guide gives the details behind the short [Deploy on AWS](../README.md#deploy-on-aws) section: IAM roles, security groups, the data-plane AMI, sizing the enclave, the data-plane bridge and SSM, running the control plane as a service, and fixes for common errors.

## What you need

| Resource | Purpose |
|---|---|
| **Control-plane EC2 instance** | Runs `admin.py` (:5000), `chat.py` (:8501) and the React UI (:8080). Any small instance type works. |
| **Data-plane AMI** | Image that `admin.py` launches the data plane from. It must already contain the repo, the Python 3.11 venv and the built `.eif` ([below](#build-the-data-plane-ami)). |
| **Two IAM roles** | One for the control plane (calls EC2, SSM and KMS) and one for the data plane (`ENCLAVE_IAM_ROLE`). |
| **Two security groups** | One per plane ([below](#security-groups)). |

## IAM

### Data-plane role (`ENCLAVE_IAM_ROLE`)

`admin.py` attaches this role to the data-plane instance as an instance profile. It needs:

- A trust policy that allows `ec2.amazonaws.com` to assume it.
- The managed policy **`AmazonSSMManagedInstanceCore`**. `admin.py` drives the instance only through SSM `send_command`, so without this policy nothing ever runs on it.
- No KMS permissions in IAM. The KMS key policy that `admin.py` creates grants this role `kms:Decrypt` (only when the attestation PCRs match) and `kms:Encrypt`.
- Nothing extra for attestation. The enclave gets its attestation document from the Nitro Security Module through `/dev/nsm`, a local device, not an AWS API.

### Control-plane role

Attach this policy to the control-plane instance's role. Replace `<ACCOUNT_ID>` and `<ENCLAVE_IAM_ROLE>`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:RunInstances",
        "ec2:StartInstances",
        "ec2:StopInstances",
        "ec2:TerminateInstances",
        "ec2:DescribeInstances",
        "ec2:CreateTags",
        "ssm:SendCommand",
        "ssm:GetCommandInvocation",
        "ssm:ListCommands",
        "ssm:ListCommandInvocations",
        "ssm:DescribeInstanceInformation",
        "kms:CreateKey",
        "kms:PutKeyPolicy",
        "kms:TagResource",
        "kms:DescribeKey",
        "kms:ScheduleKeyDeletion"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "arn:aws:iam::<ACCOUNT_ID>:role/<ENCLAVE_IAM_ROLE>"
    }
  ]
}
```

`iam:PassRole` is what lets `run_instances` attach the data-plane role. For a real deployment, narrow `Resource: "*"` down, for example to instances tagged `Name=confidential-llm-data-plane`.

**Use the instance role, not stored keys.** If `~/.aws/credentials` on the control plane holds temporary credentials, they eventually expire and every call fails with `ExpiredTokenException ... The security token included in the request is expired`. To check which credentials boto3 picks up:

```python
import boto3
print(boto3.Session().get_credentials())
# RefreshableCredentials -> instance role (good)
# Credentials            -> static or temporary keys from a file or env vars (may expire)
```

On Cloud9, also turn off *AWS managed temporary credentials* (Preferences → AWS Settings), or they override the instance role.

## Security groups

| Group | Port | Source | Used by |
|---|---|---|---|
| Control plane | 5000 | Your IP only | Admin UI (`admin.py`) |
| Control plane | 8080 | Your IP only | React chat UI |
| Control plane | 8501 | Your IP only | `chat.py` API, called from the browser |
| Control plane | 22 | Your IP only (optional) | SSH |
| Data plane | 5000 | Control plane's public IP (`/32`) | `vsock_api_server.py`, the HTTP → vsock bridge (also requires `DATA_PLANE_TOKEN`) |
| Data plane | 22 | Your IP only (optional) | SSH |

Notes:

- `chat.py` reaches the data plane on its **public** IP (`/api/dataplane/ip`), so a rule whose source is the control plane's *security group* will not match. Allow the control plane's public or Elastic IP instead, or switch the code to use `PrivateIpAddress`.
- `admin.py` requires HTTP Basic auth (`ADMIN_USER` / `ADMIN_PASSWORD`) and `chat.py`'s `/api/*` a bearer token (`API_TOKEN`) once those are set. Everything is plain HTTP, so the credentials cross the network unencrypted: keep the sources limited to your IP (or a VPN), or put a TLS proxy in front.
- The data plane's port 5000 is protected by `DATA_PLANE_TOKEN`, but still restrict it to the control plane's IP; nothing else needs to reach it.
- If the browser is not on the control-plane host, set `VITE_API_BASE_URL` in `control-plane/web/.env` to `http://<control-plane-host>:8501/api`, and add the UI's origin (`http://<control-plane-host>:8080`) to `ALLOWED_ORIGINS`.
- The data plane needs outbound HTTPS for SSM to work.

## Build the data-plane AMI

`admin.py` creates each data-plane instance from `DATA_PLANE_AMI_ID` (30 GiB root volume, enclave option on) and only sends commands to it over SSM. Everything the enclave needs must therefore already be in the AMI.

1. Launch Amazon Linux 2023 on an enclave-capable instance type (`m5.xlarge` or larger) with **Nitro Enclave enabled** under *Advanced details*, a root volume of **at least 30 GiB**, and the data-plane IAM role.
2. Install the tools and reserve enclave resources, then log out and back in:

   ```sh
   git clone <this repo> ~/confidential-llm-on-nitro-enclaves
   cd ~/confidential-llm-on-nitro-enclaves
   bash data-plane/scripts/ec2-setup.sh       # nitro-cli, docker, git, python3.11 and python3.11-pip
   ```

3. Build the enclave image as in the README, from the repo root:

   ```sh
   python3.11 -m venv ~/venv && source ~/venv/bin/activate
   pip install -r enclave/requirements.in -r data-plane/requirements.txt
   python enclave/download_model.py Qwen/Qwen2.5-0.5B-Instruct enclave/model
   docker build -f enclave/Dockerfile -t llm-enclave .
   nitro-cli build-enclave --docker-uri llm-enclave:latest --output-file enclave/llm.eif
   ```

   Use `python3.11`: AL2023's `python3` is 3.9, and the pinned dependencies need 3.10 or later. The `docker build` context must be the repo root, because the image copies `common/utils.py`. `download_model.py` writes to `./model` unless given a path, so pass `enclave/model`, which the Dockerfile copies. `enclave/llm.eif` is the default `ENCLAVE_EIF_PATH`; set that variable if you put the `.eif` elsewhere.
4. Copy `PCR0`, `PCR1` and `PCR2` from the `build-enclave` output (or `nitro-cli describe-eif --eif-path enclave/llm.eif`) into the control plane's `.env` as `ENCLAVE_PCR0..2`, and set `ENCLAVE_DEBUG_MODE=false` there. `chat.py` then accepts the enclave's key only if its attestation document carries exactly these values. They change whenever the image changes (code, pinned versions, model, base image digest), so update `.env` after every rebuild.
5. Check it once by hand: `sudo nitro-cli run-enclave --cpu-count 2 --memory 8192 --eif-path enclave/llm.eif --debug-mode --attach-console`. Wait for the model to load, then exit with `Ctrl-C` and run `sudo nitro-cli terminate-enclave --all`.
6. In the EC2 console, choose *Actions → Image and templates → Create image*. Put the resulting AMI ID in `DATA_PLANE_AMI_ID`.

Paths in the AMI must match `DATA_PLANE_REPO_DIR` and `DATA_PLANE_VENV` in `.env`. The venv at `DATA_PLANE_VENV` must be the Python 3.11 one from step 3, because `admin.py` starts `vsock_api_server.py` with it.

## Sizing the enclave

- The **allocator** reserves memory and vCPUs for enclaves when the instance boots. The default is only 512 MiB. `run-enclave` fails if you ask for more than `/etc/nitro_enclaves/allocator.yaml` reserves. `ec2-setup.sh` sets this to 8192 MiB and 2 vCPUs, matching the values `admin.py` passes. Change it with `ENCLAVE_MEMORY_MIB=… ENCLAVE_CPU_COUNT=… bash data-plane/scripts/ec2-setup.sh`.
- Give the enclave **at least 4× the `.eif` file size** in memory. The image is unpacked into RAM because the enclave has no disk.
- Reserved memory is taken away from the parent instance even when no enclave is running, so `free` on the host will show it as used. Leave enough for the parent: `m5.xlarge` (16 GiB) works with an 8 GiB enclave, and `m5.2xlarge` (the default) is more comfortable.

To change the reservation later:

```sh
sudo systemctl stop nitro-enclaves-allocator.service
sudo sed -r "s/^([[:space:]]*memory_mib[[:space:]]*:[[:space:]]*).*/\18192/" -i /etc/nitro_enclaves/allocator.yaml
sudo systemctl start nitro-enclaves-allocator.service
```

## The data-plane bridge and SSM

*Start demo* in the admin UI starts `vsock_api_server.py` on the data plane with an SSM `AWS-RunShellScript` command, then polls the bridge's `/health` for up to 60 s. Two consequences:

- **The token is visible in SSM.** `admin.py` puts `DATA_PLANE_TOKEN=…` on the command line, so it appears in the SSM command history (console, `ssm:ListCommands`, `ssm:GetCommandInvocation`). Anyone with read access to SSM in the account can see it. Limit those permissions, and rotate the token if that is not possible.
- **The bridge can be stopped after an hour.** `AWS-RunShellScript` has a default execution timeout of 3600 s. When it expires, SSM stops the command and the bridge with it, and chat requests start failing.

The alternative is to run the bridge as a systemd service baked into the AMI, with the token in a root-only file:

```ini
# /etc/systemd/system/vsock-bridge.service
[Unit]
Description=Confidential LLM data-plane bridge (vsock_api_server.py)
After=network.target nitro-enclaves-allocator.service

[Service]
# DATA_PLANE_TOKEN=<same value as on the control plane>, chmod 600
EnvironmentFile=/etc/confidential-llm/data-plane.env
Environment=PYTHONUNBUFFERED=1
ExecStart=/home/ec2-user/venv/bin/python /home/ec2-user/confidential-llm-on-nitro-enclaves/data-plane/vsock_api_server.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

This removes the timeout. `admin.py` still sends its SSM command on *Start demo* (that second copy cannot bind port 5000 and exits, while the health check is answered by the service), and it still puts the token on that command line while `DATA_PLANE_TOKEN` is set on the control plane. Keeping the token out of SSM history entirely needs a change to `admin.py` that has not been made.

## Run the control plane as a service

To keep `admin.py` running across reboots, register it with systemd. Adjust the user, paths and Python binary (3.10 or later):

```ini
# /etc/systemd/system/controlplane.service
[Unit]
Description=Confidential LLM control plane (admin.py)
After=network.target

[Service]
User=ec2-user
WorkingDirectory=/home/ec2-user/confidential-llm-on-nitro-enclaves/control-plane/api
EnvironmentFile=/home/ec2-user/confidential-llm-on-nitro-enclaves/.env
Environment=PYTHONUNBUFFERED=1
Environment="PATH=/home/ec2-user/venv/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=/home/ec2-user/venv/bin/python admin.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now controlplane.service
journalctl -u controlplane.service -f        # follow the logs
```

`PATH` must include `npm`, because *Start demo* launches the React dev server as a child process. `chat.py` is also a child process and inherits this environment, so the `.env` file must contain `API_TOKEN`, `ADMIN_USER`, `ADMIN_PASSWORD` and `DATA_PLANE_TOKEN` (and `ALLOWED_ORIGINS`, `ENCLAVE_DEBUG_MODE`, `ENCLAVE_PCR0..2`) for both apps.

## nitro-cli cheat sheet

```sh
nitro-cli describe-enclaves                               # running enclaves, their CID and PCRs
nitro-cli console --enclave-id <id>                       # attach to the console (debug mode only)
sudo nitro-cli terminate-enclave --all                    # stop every enclave
sudo nitro-cli terminate-enclave --enclave-id <id>
nitro-cli describe-eif --eif-path enclave/llm.eif         # show PCRs of an image without running it
```

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `run-enclave` reports insufficient memory or CPUs | The allocator reserves less than `--memory` / `--cpu-count` asks for. See [Sizing](#sizing-the-enclave). |
| SSM commands never run (`InvalidInstanceId`) | The data-plane role is missing `AmazonSSMManagedInstanceCore`, there is no outbound HTTPS, or the instance is still booting. |
| `ExpiredTokenException` | The control plane is using expiring credentials instead of its instance role. See [IAM](#control-plane-role). |
| Admin UI says the enclave is running but the chat times out | `vsock_api_server.py` is not running on the data plane (see [the 3600 s SSM timeout](#the-data-plane-bridge-and-ssm)), or the data plane's port 5000 is not open to the control plane's public IP. |
| *Start demo* reports "Data plane did not become ready" | The bridge did not answer `/health` within 60 s: check the SSM command's output, the venv path (`DATA_PLANE_VENV`) and the security group. |
| *Get enclave public key* fails with "Attestation verification failed, server key NOT stored: …" | The message lists the failed checks. Usually `ENCLAVE_PCR0..2` are missing or from an older build, or `ENCLAVE_DEBUG_MODE` differs from how the enclave was started. "the enclave returned no attestation document" means the enclave could not reach `/dev/nsm`. |
| `chat.py` answers 401, or the browser reports a CORS error | `VITE_API_TOKEN` in `control-plane/web/.env` differs from `API_TOKEN`, or the UI's origin is not in `ALLOWED_ORIGINS`. |
| `pip install` fails to find the pinned versions | The venv was made with AL2023's `python3` (3.9). Recreate it with `python3.11`. |
| `build-enclave` fails or the disk fills up | The root volume is too small for Docker layers plus model weights. Use 30 GiB or more. |
| PCRs are all zeros | The enclave runs with `--debug-mode`, and `chat.py` reports the attestation mode as `debug`. Attestation only identifies the image with `ENCLAVE_DEBUG_MODE=false`. |
