from flask import Flask, render_template, jsonify
import boto3 
from botocore.config import Config
import time
import psutil
import os
import signal
import sys
import shlex
import subprocess
import json
import requests
from auth import require_basic


def env_list(name):
    return [v.strip() for v in os.environ.get(name, "").split(",") if v.strip()]


AWS_ACCOUNT_ID       = os.environ["AWS_ACCOUNT_ID"]
ENCLAVE_IAM_ROLE     = os.environ.get("ENCLAVE_IAM_ROLE", "ConfidentialLLMEnclave")
ENCLAVE_PCR0         = os.environ.get("ENCLAVE_PCR0", "")
ENCLAVE_PCR1         = os.environ.get("ENCLAVE_PCR1", "")
ENCLAVE_PCR2         = os.environ.get("ENCLAVE_PCR2", "")
DATA_PLANE_AMI_ID    = os.environ["DATA_PLANE_AMI_ID"]
DATA_PLANE_INSTANCE_TYPE = os.environ.get("DATA_PLANE_INSTANCE_TYPE", "m5.2xlarge")
DATA_PLANE_KEY_NAME  = os.environ.get("DATA_PLANE_KEY_NAME", "")
DATA_PLANE_SECURITY_GROUP_IDS = env_list("DATA_PLANE_SECURITY_GROUP_IDS")
CONTROL_PLANE_INSTANCE_IDS    = env_list("CONTROL_PLANE_INSTANCE_IDS")
DATA_PLANE_REPO_DIR  = os.environ.get("DATA_PLANE_REPO_DIR", "/home/ec2-user/confidential-llm-on-nitro-enclaves")
DATA_PLANE_VENV      = os.environ.get("DATA_PLANE_VENV", "/home/ec2-user/venv")
ENCLAVE_EIF_PATH     = os.environ.get("ENCLAVE_EIF_PATH", f"{DATA_PLANE_REPO_DIR}/enclave/llm.eif")
ENCLAVE_DEBUG_MODE   = os.environ.get("ENCLAVE_DEBUG_MODE", "true").lower() == "true"
DEMO_URL             = os.environ.get("DEMO_URL", "http://localhost:8080")
DATA_PLANE_TOKEN     = os.environ.get("DATA_PLANE_TOKEN", "")   # bearer token for vsock_api_server.py
CHAT_HEALTH_URL      = "http://localhost:8501/health"           # chat.py started by start_demo
WEB_DEV_URL          = "http://localhost:8080"                  # React dev server (vite.config.ts)

API_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(API_DIR, "..", "web")


policy_dict = {
  "Version": "2012-10-17",
  "Id": "key-consolepolicy-3",
  "Statement": [
    {
      "Sid": "Enable IAM User Permissions",
      "Effect": "Allow",
      "Principal": { "AWS": f"arn:aws:iam::{AWS_ACCOUNT_ID}:root" },
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Sid": "Enable decrypt from enclave",
      "Effect": "Allow",
      "Principal": { "AWS": f"arn:aws:iam::{AWS_ACCOUNT_ID}:role/{ENCLAVE_IAM_ROLE}" },
      "Action": "kms:Decrypt",
      "Resource": "*",
      "Condition": {
        # Case-insensitive string match is supported in IAM conditions.
        "StringEqualsIgnoreCase": {
          "kms:RecipientAttestation:PCR0": ENCLAVE_PCR0,
          "kms:RecipientAttestation:PCR1": ENCLAVE_PCR1,
          "kms:RecipientAttestation:PCR2": ENCLAVE_PCR2
        }
      }
    },
    {
      "Sid": "Enable encrypt from instance",
      "Effect": "Allow",
      "Principal": { "AWS": f"arn:aws:iam::{AWS_ACCOUNT_ID}:role/{ENCLAVE_IAM_ROLE}" },
      "Action": "kms:Encrypt",
      "Resource": "*"
    },
    {
      "Sid": "Allow access for Key Administrators",
      "Effect": "Allow",
      "Principal": { "AWS": f"arn:aws:iam::{AWS_ACCOUNT_ID}:role/{ENCLAVE_IAM_ROLE}" },
      "Action": [
        "kms:Create*","kms:Describe*","kms:Enable*","kms:List*","kms:Put*","kms:Update*",
        "kms:Revoke*","kms:Disable*","kms:Get*","kms:Delete*","kms:TagResource","kms:UntagResource",
        "kms:ScheduleKeyDeletion","kms:CancelKeyDeletion"
      ],
      "Resource": "*"
    }
  ]
}

policy_json = json.dumps(policy_dict)


region = os.environ.get('AWS_REGION', 'ap-northeast-1')
config = Config( 
    region_name = region,
    signature_version = 'v4',
    retries = {
        'max_attempts': 10,
        'mode': 'standard'
    }
)

ec2 = boto3.client('ec2', config = config)
kms = boto3.client("kms", config = config)
control_plane_instances = CONTROL_PLANE_INSTANCE_IDS
data_plane_instances = [] # IDs of data-plane instances created by this process
session = boto3.Session()
ssm_client = boto3.client('ssm', config = config)

app = Flask(__name__)
app.before_request(require_basic("ADMIN_USER", "ADMIN_PASSWORD"))

# In-process state
instance_created = False
instance_working = False
tee_status = False
demo_status = False
demo_url = None
react_process = None
chat_process = None
key_id = None


def wait_for_ssm_command(command_id, instance_id, timeout):
    """Poll an SSM command until it leaves Pending/InProgress; return the invocation."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            invocation = ssm_client.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
            if invocation['Status'] not in ('Pending', 'InProgress', 'Delayed'):
                return invocation
        except ssm_client.exceptions.InvocationDoesNotExist:
            pass  # not registered yet right after send_command
        if time.monotonic() > deadline:
            raise TimeoutError(f"SSM command {command_id} did not finish within {timeout}s")
        time.sleep(0.5)


def wait_for_http(url, timeout):
    """Poll url until it answers 200; return False if it does not within timeout seconds."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if requests.get(url, timeout=2).status_code == 200:
                return True
        except requests.RequestException:
            pass
        time.sleep(0.5)
    return False

def stop_process_by_name(name_substring):
    """Stop any process whose name or command line contains the substring."""
    stopped = False
    for proc in psutil.process_iter(attrs=['pid', 'name', 'cmdline']):
        try:
            cmdline = proc.info.get('cmdline')
            if not cmdline or not isinstance(cmdline, list):
                continue  # skip None or malformed entries

            cmd = ' '.join(str(part) for part in cmdline if part)
            name = proc.info.get('name', '')

            if name_substring in name or name_substring in cmd:
                os.kill(proc.info['pid'], signal.SIGTERM)
                print(f"Stopped process: {name} (PID: {proc.info['pid']})")
                stopped = True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return stopped



@app.route('/')
def index():
    return render_template('index.html', 
                         instance_working=instance_working,
                         tee_status=tee_status)

### NEW
@app.route('/api/instance/create', methods=['POST'])
def create_instance():
    global instance_created, instance_working, data_plane_instances
    try:
        response = ec2.run_instances(
            BlockDeviceMappings=[
                {
                    'DeviceName': '/dev/xvda',
                    'Ebs': {
                        'VolumeSize': 30,
                    }
                }
            ],
            ImageId=DATA_PLANE_AMI_ID,
            InstanceType=DATA_PLANE_INSTANCE_TYPE,      # 'm5.xlarge' or 'm5.2xlarge' or 'm5.4xlarge'
            MinCount=1,
            MaxCount=1,
            KeyName=DATA_PLANE_KEY_NAME,
            EnclaveOptions={'Enabled': True},
            SecurityGroupIds=DATA_PLANE_SECURITY_GROUP_IDS,
            IamInstanceProfile={'Name': ENCLAVE_IAM_ROLE},
            TagSpecifications=[
                {
                    'ResourceType': 'instance',
                    'Tags': [
                        {'Key': 'Name', 'Value': 'confidential-llm-data-plane'}
                    ]
                }
            ]
        )
        data_plane_instances = [response['Instances'][0]['InstanceId']]
        print(f"Instance created: {data_plane_instances}")
        
        # Wait until the instance is running
        ec2.get_waiter('instance_running').wait(InstanceIds=data_plane_instances)
        
        instance_created = True
        instance_working = True
        return jsonify({"success": True, "message": "Instance created"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})


# Return the data-plane public IP
def dataplane_public_ip():
    instance_id = data_plane_instances[0]
    ec2_response = ec2.describe_instances(InstanceIds=[instance_id])
    return ec2_response['Reservations'][0]['Instances'][0]['PublicIpAddress']


@app.route('/api/dataplane/ip')
def get_dataplane_ip():
    try:
        return jsonify({'ip': dataplane_public_ip()})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/instance/delete', methods=['POST'])
def delete_instance():
    global instance_created, data_plane_instances
    try:
        ec2.terminate_instances(InstanceIds=data_plane_instances)
        data_plane_instances = []
        instance_created = False
        return jsonify({"success": True, "message": "Instance terminated"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})
### NEW

@app.route('/api/instance/start', methods=['POST'])
def start_instance():
    global instance_working
    try:
        ec2.start_instances(InstanceIds=data_plane_instances)
        instance_working = True
        return jsonify({"success": True, "message": "Instance started"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

@app.route('/api/instance/stop', methods=['POST'])
def stop_instance():
    global instance_working
    try:
        ec2.stop_instances(InstanceIds=data_plane_instances)
        instance_working = False
        return jsonify({"success": True, "message": "Instance stopped"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

@app.route('/api/tee/start', methods=['POST'])
def start_tee():
    global tee_status, key_id
    try:
        resp = kms.create_key(
            Description="LLM on Nitro Enclaves key",
            KeyUsage="ENCRYPT_DECRYPT",          # symmetric data key use
            KeySpec="SYMMETRIC_DEFAULT",         # AES-256 KMS key
            Policy=policy_json,                  # your policy as a JSON string
        )
        key_id = resp["KeyMetadata"]["KeyId"]
        print("Created KMS key:", key_id)

        response = ssm_client.send_command(
            InstanceIds=data_plane_instances,
            DocumentName='AWS-RunShellScript',
            Parameters={
                'commands': [
                    f'source {DATA_PLANE_VENV}/bin/activate',
                    f'sudo nitro-cli run-enclave --cpu-count 2 --memory 8192 --eif-path {ENCLAVE_EIF_PATH}'
                    + (' --debug-mode --attach-console' if ENCLAVE_DEBUG_MODE else '')
                ]
            }
        )
        command_id = response['Command']['CommandId']
        print(f"Nitro-enclave activation command sent. Command ID: {command_id}")
        
        tee_status = True
        return jsonify({"success": True, "message": "Enclave started"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

@app.route('/api/tee/stop', methods=['POST'])
def stop_tee():
    global tee_status, key_id
    try:
        response = ssm_client.send_command(
            InstanceIds=data_plane_instances,
            DocumentName='AWS-RunShellScript',
            Parameters={
                'commands': ['sudo nitro-cli terminate-enclave --all']
            }
        )
        command_id = response['Command']['CommandId']
        print(f"Nitro-enclave termination command sent. Command ID: {command_id}")
        
        kms.schedule_key_deletion(
            KeyId=key_id,
            PendingWindowInDays=7
        )
        print(f"Scheduled deletion for key {key_id}")
        key_id = None  # reset after scheduling deletion

        tee_status = False
        return jsonify({"success": True, "message": "Enclave stopped"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

@app.route('/api/tee/status', methods=['GET'])
def tee_ready_status():
    try:
        response = ssm_client.send_command(
            InstanceIds=data_plane_instances,
            DocumentName='AWS-RunShellScript',
            Parameters={'commands': ['sudo nitro-cli describe-enclaves']}
        )
        output = wait_for_ssm_command(response['Command']['CommandId'], data_plane_instances[0], timeout=30)
        # Check whether the output reports a running enclave
        if "RUNNING" in output.get('StandardOutputContent', ''):
            return jsonify({"ready": True})
        return jsonify({"ready": False})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/demo/start', methods=['POST'])
def start_demo():
    global demo_status, demo_url, react_process, chat_process
    if not instance_created:
        return jsonify({
            "success": False,
            "message": "No instance exists. Create the instance first."
        }), 400
    if not instance_working:
        return jsonify({
            "success": False,
            "message": "The instance is not running. Start it first."
        }), 400
    if not tee_status:
        return jsonify({
            "success": False,
            "message": "The enclave is not running. Start it first."
        }), 400

    try:
        # Start the HTTP->vsock bridge on the data plane (long-running, so wait for /health instead
        # of the SSM command). ENCLAVE_LOG_PLAINTEXT is deliberately never set here.
        token_env = f'DATA_PLANE_TOKEN={shlex.quote(DATA_PLANE_TOKEN)} ' if DATA_PLANE_TOKEN else ''
        response = ssm_client.send_command(
            InstanceIds=data_plane_instances,
            DocumentName='AWS-RunShellScript',
            Parameters={
                'commands': [
                    f'source {DATA_PLANE_VENV}/bin/activate',
                    f'{token_env}python3 {DATA_PLANE_REPO_DIR}/data-plane/vsock_api_server.py'
                ]
            }
        )
        command_id = response['Command']['CommandId']
        print(f"vsock_api_server.py command sent. Command ID: {command_id}")

        # Wait for vsock_api_server.py to come up
        data_plane_health = f"http://{dataplane_public_ip()}:5000/health"
        if not wait_for_http(data_plane_health, timeout=60):
            return jsonify({"success": False, "message": f"Data plane did not become ready ({data_plane_health})"})

        # Start chat.py (inherits this environment: API_TOKEN, DATA_PLANE_TOKEN, ADMIN_USER, ...)
        if chat_process is None or chat_process.poll() is not None:
            chat_process = subprocess.Popen(
                [sys.executable, os.path.join(API_DIR, "chat.py")]
            )
            print("Running chat.py at port 8501")
        if not wait_for_http(CHAT_HEALTH_URL, timeout=30):
            return jsonify({"success": False, "message": "chat.py did not become ready on port 8501"})
        
        # Start the React app
        if react_process is None:
            react_process = subprocess.Popen(
                ["npm", "run", "dev"],
                cwd=WEB_DIR,
                stdout=subprocess.DEVNULL,   # never read: a full pipe would block Vite
                stderr=subprocess.DEVNULL
            )
            print("React app started on port 8080")
        else:
            print("React app already running")
        
        # Wait for the React dev server
        if not wait_for_http(WEB_DEV_URL, timeout=60):
            return jsonify({"success": False, "message": f"React dev server did not become ready ({WEB_DEV_URL})"})

        demo_status = True
        demo_url = DEMO_URL
        
        return jsonify({
            "success": True,
            "message": "Demo started",
            "url": demo_url
        })
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

@app.route('/api/stop_demo', methods=['POST'])
def stop_demo():
    global react_process, demo_status, demo_url, chat_process

    # Stop the React app
    if react_process is not None:
        react_process.terminate()
        react_process = None
        react_stopped = True
        print("React app terminated")
    else:
        react_stopped = False
        print("React app was not running")

    # Stop chat.py
    if chat_process is not None:
        chat_process.terminate()
        chat_process = None
        chat_stopped = True
        print("chat.py terminated")
    else:
        chat_stopped = False
        print("chat.py was not running")

    # Reset status
    demo_status = False
    demo_url = None

    return jsonify({
        "react_stopped": react_stopped,
        "chat_stopped": chat_stopped
    })

@app.route('/api/status', methods=['GET'])
def get_status():
    # Fetch the EC2 instance state
    instance_status = "stopped"
    if data_plane_instances:
        try:
            ec2_response = ec2.describe_instances(InstanceIds=data_plane_instances)
            instance_state = ec2_response['Reservations'][0]['Instances'][0]['State']['Name']
            instance_status = instance_state  # e.g., 'running', 'stopped', etc.
        except Exception as e:
            print(f"[WARN] failed to fetch instance state: {e}")

    return jsonify({
        "instance_created": bool(data_plane_instances),
        "instance_working": instance_status == "running",
        "tee_status": tee_status,
        "demo_running": demo_status,
        "demo_url": demo_url
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)