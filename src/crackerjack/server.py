"""Zero-dependency REST API microservice powered by Python's ThreadingHTTPServer."""

from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from crackerjack import __version__
from crackerjack.auditor import evaluate_password
from crackerjack.generator import generate_passphrase
from crackerjack.vault import GLOBAL_VAULT


def get_openapi_spec() -> dict[str, Any]:
    """Return the OpenAPI 3.0 schema for the Crackerjack API."""
    return {
        "openapi": "3.0.0",
        "info": {
            "title": "Crackerjack Password Governance & Policy API",
            "version": __version__,
            "description": "High-performance REST API for NIST SP 800-63B password policy scoring, k-anonymity breach validation, and passphrase generation.",
        },
        "paths": {
            "/v1/health": {
                "get": {
                    "summary": "Health check",
                    "responses": {
                        "200": {
                            "description": "Service is healthy",
                            "content": {"application/json": {"schema": {"type": "object"}}},
                        }
                    },
                }
            },
            "/v1/validate": {
                "post": {
                    "summary": "Fast boolean validation for user registration/password reset",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "password": {"type": "string"},
                                        "context": {"type": "array", "items": {"type": "string"}},
                                        "min_score": {"type": "integer", "default": 65},
                                        "min_grade": {"type": "string", "default": "C"},
                                        "check_breach": {"type": "boolean", "default": True},
                                    },
                                    "required": ["password"],
                                }
                            }
                        },
                    },
                    "responses": {"200": {"description": "Validation verdict"}},
                }
            },
            "/v1/evaluate": {
                "post": {
                    "summary": "Detailed NIST SP 800-63B audit and entropy analysis",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "password": {"type": "string"},
                                        "context": {"type": "array", "items": {"type": "string"}},
                                        "check_breach": {"type": "boolean", "default": True},
                                    },
                                    "required": ["password"],
                                }
                            }
                        },
                    },
                    "responses": {"200": {"description": "Complete evaluation results"}},
                }
            },
            "/v1/generate": {
                "post": {
                    "summary": "Generate NIST-compliant multi-word passphrase with certified entropy",
                    "requestBody": {
                        "required": False,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "words": {"type": "integer", "default": 4},
                                        "separator": {"type": "string", "default": "-"},
                                        "capitalize": {"type": "boolean", "default": False},
                                        "add_number": {"type": "boolean", "default": True},
                                        "add_symbol": {"type": "boolean", "default": False},
                                        "check_breach": {"type": "boolean", "default": False},
                                    },
                                }
                            }
                        },
                    },
                    "responses": {"200": {"description": "Generated passphrase"}},
                }
            },
            "/v1/vault": {
                "post": {
                    "summary": "Store zero-knowledge encrypted ephemeral secret (client-side AES-256-GCM)",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "id": {"type": "string", "example": "vlt_8fa72c019a"},
                                        "ciphertext": {"type": "string", "description": "URL-safe base64 combined IV + ciphertext + tag"},
                                        "burn_on_read": {"type": "boolean", "default": True},
                                        "expires_at": {"type": "integer", "description": "Unix timestamp in seconds"},
                                        "allow_ip": {"type": "string", "nullable": True, "description": "Optional IP or CIDR mask"},
                                    },
                                    "required": ["id", "ciphertext", "expires_at"],
                                }
                            }
                        },
                    },
                    "responses": {
                        "201": {"description": "Secret stored in ephemeral memory"},
                        "400": {"description": "Invalid payload"},
                    },
                }
            },
            "/v1/vault/{id}": {
                "get": {
                    "summary": "Fetch and optionally self-destruct an encrypted secret",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                            "description": "Unique secret identifier",
                        }
                    ],
                    "responses": {
                        "200": {"description": "Encrypted secret payload"},
                        "403": {"description": "Access denied: IP geofence restriction violated"},
                        "404": {"description": "Secret not found, expired, or already burned"},
                    },
                }
            },
        },
    }


def get_docs_html() -> str:
    """Return interactive Swagger UI documentation page."""
    return f"""<!DOCTYPE html>
<html>
<head>
    <title>Crackerjack API Documentation</title>
    <link rel="stylesheet" type="text/css" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css" />
    <style>
        body {{ margin: 0; padding: 0; }}
        .topbar {{ display: none; }}
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
        window.onload = function() {{
            SwaggerUIBundle({{
                url: "/openapi.json",
                dom_id: "#swagger-ui",
                deepLinking: true,
                presets: [
                    SwaggerUIBundle.presets.apis,
                    SwaggerUIBundle.SwaggerUIStandalonePreset
                ],
                layout: "BaseLayout"
            }});
        }};
    </script>
</body>
</html>
"""


class CrackerjackRequestHandler(BaseHTTPRequestHandler):
    """HTTP Request handler supporting CORS, JSON payloads, and REST routing."""

    server_version = f"CrackerjackAPI/{__version__}"

    def _send_cors_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def _send_json_response(self, status: int, data: Any) -> None:
        payload = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(payload)

    def do_OPTIONS(self) -> None:
        self.send_response(HTTPStatus.NO_CONTENT)
        self._send_cors_headers()
        self.end_headers()

    def do_GET(self) -> None:
        path = self.path.split("?")[0].rstrip("/")

        if path in ("/v1/health", "/health"):
            self._send_json_response(
                HTTPStatus.OK,
                {"status": "healthy", "service": "crackerjack-api", "version": __version__},
            )
        elif path == "/openapi.json":
            self._send_json_response(HTTPStatus.OK, get_openapi_spec())
        elif path == "":
            web_file = Path(__file__).resolve().parent.parent.parent / "web" / "index.html"
            if not web_file.exists():
                web_file = Path.cwd() / "web" / "index.html"

            if web_file.exists():
                html = web_file.read_bytes()
            else:
                html = get_docs_html().encode("utf-8")

            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(html)
        elif path in ("/docs", "/api/docs"):
            html = get_docs_html().encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            self._send_cors_headers()
            self.end_headers()
            self.wfile.write(html)
        elif path.startswith("/v1/vault/"):
            secret_id = path[len("/v1/vault/"):].strip("/")
            if not secret_id:
                self._send_json_response(HTTPStatus.BAD_REQUEST, {"error": "Missing secret ID in path"})
                return
            client_ip = (
                self.headers.get("CF-Connecting-IP")
                or self.headers.get("X-Forwarded-For", "").split(",")[0].strip()
                or (self.client_address[0] if hasattr(self, "client_address") and self.client_address else None)
            )
            try:
                record = GLOBAL_VAULT.get(secret_id, client_ip=client_ip)
                if not record:
                    self._send_json_response(
                        HTTPStatus.NOT_FOUND,
                        {"error": "Secret not found, expired, or already burned."},
                    )
                else:
                    self._send_json_response(HTTPStatus.OK, record)
            except PermissionError as pe:
                self._send_json_response(HTTPStatus.FORBIDDEN, {"error": str(pe)})
        else:
            self._send_json_response(HTTPStatus.NOT_FOUND, {"error": "Not found", "path": path})

    def do_POST(self) -> None:
        path = self.path.split("?")[0].rstrip("/")
        content_length = int(self.headers.get("Content-Length", 0))

        body: dict[str, Any] = {}
        if content_length > 0:
            try:
                raw_body = self.rfile.read(content_length).decode("utf-8")
                body = json.loads(raw_body)
            except Exception as e:
                self._send_json_response(
                    HTTPStatus.BAD_REQUEST,
                    {"error": f"Invalid JSON payload: {str(e)}"},
                )
                return

        if path == "/v1/evaluate":
            self._handle_evaluate(body)
        elif path == "/v1/validate":
            self._handle_validate(body)
        elif path == "/v1/generate":
            self._handle_generate(body)
        elif path == "/v1/vault":
            self._handle_vault(body)
        else:
            self._send_json_response(HTTPStatus.NOT_FOUND, {"error": "Not found", "path": path})

    def _handle_evaluate(self, body: dict[str, Any]) -> None:
        password = body.get("password")
        if not password:
            self._send_json_response(
                HTTPStatus.BAD_REQUEST,
                {"error": "Missing required 'password' field in request body."},
            )
            return

        context_terms = body.get("context", [])
        if isinstance(context_terms, str):
            context_terms = [t.strip() for t in context_terms.split(",") if t.strip()]

        check_breach = body.get("check_breach", True)

        nist = evaluate_password(password, context_terms=context_terms)
        breach_dict = {"pwned": False, "breach_count": 0, "offline": True}

        if check_breach:
            try:
                from crackerjack.breach import check_password_breached
                b_info = check_password_breached(password)
                breach_dict = b_info.to_dict()
            except Exception as e:
                breach_dict["status_message"] = f"Breach check error: {str(e)}"

        allowed = (
            nist.passed_min_length
            and nist.score >= 60
            and not breach_dict.get("pwned", False)
            and not nist.has_context_words
        )

        response = {
            "allowed": allowed,
            "score": nist.score,
            "grade": nist.grade,
            "nist": nist.to_dict(),
            "breach": breach_dict,
        }
        self._send_json_response(HTTPStatus.OK, response)

    def _handle_validate(self, body: dict[str, Any]) -> None:
        password = body.get("password")
        if not password:
            self._send_json_response(
                HTTPStatus.BAD_REQUEST,
                {"error": "Missing required 'password' field in request body."},
            )
            return

        context_terms = body.get("context", [])
        if isinstance(context_terms, str):
            context_terms = [t.strip() for t in context_terms.split(",") if t.strip()]

        min_score = body.get("min_score", 65)
        check_breach = body.get("check_breach", True)

        nist = evaluate_password(password, context_terms=context_terms)
        violations: list[str] = []

        if not nist.passed_min_length:
            violations.append("Password does not meet minimum length requirement (8+ characters).")
        if nist.has_context_words:
            violations.append(f"Contains context-specific terms: {', '.join(nist.matched_context_terms)}")
        if nist.is_dictionary_word:
            violations.append("Contains common dictionary word root.")
        if nist.has_sequential_pattern or nist.has_repetitive_pattern:
            violations.append("Contains repetitive or keyboard-walk sequence.")
        if nist.score < min_score:
            violations.append(f"Score {nist.score}/100 is below required minimum of {min_score}.")

        is_pwned = False
        breach_count = 0
        if check_breach:
            try:
                from crackerjack.breach import check_password_breached
                b = check_password_breached(password)
                if b.pwned:
                    is_pwned = True
                    breach_count = b.breach_count
                    violations.append(f"CRITICAL: Found in {breach_count:,} public data breaches!")
            except Exception:
                pass

        allowed = len(violations) == 0

        self._send_json_response(
            HTTPStatus.OK,
            {
                "allowed": allowed,
                "score": nist.score,
                "grade": nist.grade,
                "breached": is_pwned,
                "breach_count": breach_count,
                "violations": violations,
                "recommendations": nist.recommendations,
            },
        )

    def _handle_generate(self, body: dict[str, Any]) -> None:
        words = body.get("words", 4)
        separator = body.get("separator", "-")
        capitalize = body.get("capitalize", False)
        add_number = body.get("add_number", True)
        add_symbol = body.get("add_symbol", False)
        check_breach = body.get("check_breach", False)

        generated = generate_passphrase(
            word_count=words,
            separator=separator,
            capitalize=capitalize,
            add_number=add_number,
            add_symbol=add_symbol,
            check_breach=check_breach,
        )
        self._send_json_response(HTTPStatus.OK, generated.to_dict())

    def _handle_vault(self, body: dict[str, Any]) -> None:
        secret_id = body.get("id")
        ciphertext = body.get("ciphertext")
        expires_at = body.get("expires_at")
        if not secret_id or not ciphertext or not expires_at:
            self._send_json_response(
                HTTPStatus.BAD_REQUEST,
                {"error": "Missing required fields ('id', 'ciphertext', 'expires_at') for vault secret."},
            )
            return

        record = GLOBAL_VAULT.put(body)
        self._send_json_response(HTTPStatus.CREATED, record)

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress default stderr HTTP request logging for clean terminal output."""
        return


def create_server(host: str = "0.0.0.0", port: int = 8000) -> ThreadingHTTPServer:
    """Create and configure the ThreadingHTTPServer instance."""
    return ThreadingHTTPServer((host, port), CrackerjackRequestHandler)


def run_server(host: str = "0.0.0.0", port: int = 8000) -> None:
    """Start the Crackerjack REST API server."""
    server = create_server(host, port)
    print(f"🚀 Crackerjack REST API v{__version__} listening on http://{host}:{port}")
    print(f"📖 Interactive Swagger Docs: http://{host}:{port}/docs")
    print(f"⚡ Endpoints:")
    print(f"   - GET  /v1/health")
    print(f"   - POST /v1/validate")
    print(f"   - POST /v1/evaluate")
    print(f"   - POST /v1/generate")
    print(f"   - POST /v1/vault")
    print(f"   - GET  /v1/vault/{{id}}")
    print(f"   - GET  /openapi.json")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 Shutting down Crackerjack API server...")
        server.shutdown()
        server.server_close()
