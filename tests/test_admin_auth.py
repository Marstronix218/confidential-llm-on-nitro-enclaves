"""control-plane/api/admin.py: Basic auth + CSRF header, and its readiness polling helpers.

admin.py builds boto3 clients at import time; that works offline (no API call is made), and the
tests that touch AWS use botocore's Stubber, so no credentials or network are needed.
"""
import base64
import importlib
import socket
import sys

import pytest
from botocore.stub import Stubber

ADMIN_USER, ADMIN_PASSWORD = "admin", "admin-password"
BASIC = {"Authorization": "Basic " + base64.b64encode(f"{ADMIN_USER}:{ADMIN_PASSWORD}".encode()).decode()}
XHR = {"X-Requested-With": "XMLHttpRequest"}


@pytest.fixture
def admin(monkeypatch):
    monkeypatch.setenv("AWS_ACCOUNT_ID", "123456789012")
    monkeypatch.setenv("DATA_PLANE_AMI_ID", "ami-0123456789abcdef0")
    monkeypatch.setenv("AWS_REGION", "ap-northeast-1")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")       # never used: every AWS call is stubbed
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("ADMIN_USER", ADMIN_USER)
    monkeypatch.setenv("ADMIN_PASSWORD", ADMIN_PASSWORD)
    sys.modules.pop("admin", None)
    module = importlib.import_module("admin")
    yield module
    sys.modules.pop("admin", None)


@pytest.fixture
def client(admin):
    return admin.app.test_client()


@pytest.mark.parametrize("method, path", [("GET", "/api/status"), ("POST", "/api/stop_demo"), ("GET", "/")])
def test_requires_basic_auth(client, method, path):
    response = client.open(path, method=method, headers=XHR)
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"].startswith("Basic")


def test_wrong_password_is_rejected(client):
    bad = {"Authorization": "Basic " + base64.b64encode(f"{ADMIN_USER}:wrong".encode()).decode()}
    assert client.post("/api/stop_demo", headers={**bad, **XHR}).status_code == 401


def test_post_without_csrf_header_is_forbidden(client, admin):
    response = client.post("/api/stop_demo", headers=BASIC)
    assert response.status_code == 403
    assert "X-Requested-With" in response.get_json()["message"]


def test_post_with_auth_and_csrf_header(client):
    response = client.post("/api/stop_demo", headers={**BASIC, **XHR})
    assert response.status_code == 200
    assert response.get_json() == {"react_stopped": False, "chat_stopped": False}


def test_get_needs_no_csrf_header(client):
    assert client.get("/api/status", headers=BASIC).status_code == 200


def test_csrf_header_required_even_without_basic_auth(monkeypatch, admin):
    monkeypatch.delenv("ADMIN_USER")
    monkeypatch.delenv("ADMIN_PASSWORD")
    sys.modules.pop("admin", None)
    unauthenticated = importlib.import_module("admin").app.test_client()
    assert unauthenticated.post("/api/stop_demo").status_code == 403
    assert unauthenticated.post("/api/stop_demo", headers=XHR).status_code == 200


COMMAND_ID = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"   # SSM validates the 36-character format
INSTANCE_ID = "i-0123456789abcdef0"


def invocation(status):
    return {"CommandId": COMMAND_ID, "InstanceId": INSTANCE_ID, "Status": status}


def test_wait_for_ssm_command_polls_until_done(admin, monkeypatch):
    monkeypatch.setattr(admin.time, "sleep", lambda seconds: None)
    params = {"CommandId": COMMAND_ID, "InstanceId": INSTANCE_ID}
    with Stubber(admin.ssm_client) as stub:
        stub.add_client_error("get_command_invocation", service_error_code="InvocationDoesNotExist",
                              expected_params=params)
        stub.add_response("get_command_invocation", invocation("Pending"), params)
        stub.add_response("get_command_invocation", invocation("InProgress"), params)
        stub.add_response("get_command_invocation", invocation("Success"), params)

        result = admin.wait_for_ssm_command(COMMAND_ID, INSTANCE_ID, timeout=30)

        stub.assert_no_pending_responses()
    assert result["Status"] == "Success"


def test_wait_for_ssm_command_times_out(admin, monkeypatch):
    monkeypatch.setattr(admin.time, "sleep", lambda seconds: None)
    with Stubber(admin.ssm_client) as stub:
        stub.add_response("get_command_invocation", invocation("InProgress"))
        with pytest.raises(TimeoutError):
            admin.wait_for_ssm_command(COMMAND_ID, INSTANCE_ID, timeout=0)


def test_wait_for_http_gives_up_on_a_closed_port(admin):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]   # nothing listens once the socket is closed
    assert admin.wait_for_http(f"http://127.0.0.1:{port}/health", timeout=1) is False
