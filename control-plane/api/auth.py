"""Shared request authentication for chat.py and admin.py.

Both helpers read their secrets from the environment once, when the app is set up, and return a
Flask before_request hook. If the env vars are unset, auth is disabled and a warning is logged.

    app.before_request(require_bearer("API_TOKEN", path_prefix="/api/"))
    app.before_request(require_basic("ADMIN_USER", "ADMIN_PASSWORD"))

require_basic also rejects state-changing requests (anything but GET/HEAD/OPTIONS) that lack
`X-Requested-With: XMLHttpRequest`. A cross-site form cannot set that header and a cross-site fetch
that sets it needs a CORS preflight, which the admin app never grants, so browsers' cached Basic
credentials cannot be used for CSRF.
"""
import hmac
import logging
import os

from flask import Response, jsonify, request

log = logging.getLogger(__name__)

SAFE_METHODS = ("GET", "HEAD", "OPTIONS")


def _equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def require_bearer(token_env: str, path_prefix: str = "/"):
    """Require `Authorization: Bearer $<token_env>` on paths starting with path_prefix."""
    token = os.environ.get(token_env, "")
    if not token:
        log.warning("%s is not set: bearer authentication is DISABLED", token_env)

    def check():
        if not token or request.method == "OPTIONS" or not request.path.startswith(path_prefix):
            return None  # CORS preflights carry no credentials
        header = request.headers.get("Authorization", "")
        scheme, _, value = header.partition(" ")
        if scheme.lower() == "bearer" and _equal(value.strip(), token):
            return None
        return jsonify({"status": "error", "message": "Unauthorized"}), 401

    return check


def require_basic(user_env: str, password_env: str, realm: str = "admin"):
    """Require HTTP Basic auth with $<user_env> / $<password_env> on every route, and the
    X-Requested-With: XMLHttpRequest header on state-changing methods (CSRF; enforced even without auth)."""
    user = os.environ.get(user_env, "")
    password = os.environ.get(password_env, "")
    if not (user and password):
        log.warning("%s / %s are not set: basic authentication is DISABLED", user_env, password_env)

    def check():
        if user and password:
            auth = request.authorization
            if not (auth and auth.type == "basic" and _equal(auth.username or "", user)
                    and _equal(auth.password or "", password)):
                return Response("Unauthorized", 401, {"WWW-Authenticate": f'Basic realm="{realm}"'})
        if request.method not in SAFE_METHODS and request.headers.get("X-Requested-With") != "XMLHttpRequest":
            return jsonify({"success": False, "message": "Missing X-Requested-With: XMLHttpRequest header"}), 403
        return None

    return check


def basic_auth_from_env(user_env: str, password_env: str):
    """(user, password) for `requests` calls to a Basic-protected service, or None when unset."""
    user = os.environ.get(user_env, "")
    password = os.environ.get(password_env, "")
    return (user, password) if user and password else None


def bearer_headers_from_env(token_env: str) -> dict:
    """Authorization header for `requests` calls to a bearer-protected service ({} when unset)."""
    token = os.environ.get(token_env, "")
    return {"Authorization": f"Bearer {token}"} if token else {}
