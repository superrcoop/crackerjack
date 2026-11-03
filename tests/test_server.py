"""Tests for REST API microservice and OpenAPI specification."""

from io import BytesIO
import json
import threading
from typing import Any
import urllib.request
from http import HTTPStatus

from crackerjack.server import CrackerjackRequestHandler, create_server, get_docs_html, get_openapi_spec


def test_openapi_spec():
    spec = get_openapi_spec()
    assert spec["openapi"] == "3.0.0"
    assert "/v1/health" in spec["paths"]
    assert "/v1/validate" in spec["paths"]
    assert "/v1/evaluate" in spec["paths"]
    assert "/v1/generate" in spec["paths"]


def test_docs_html():
    html = get_docs_html()
    assert "<!DOCTYPE html>" in html
    assert "SwaggerUIBundle" in html
    assert "/openapi.json" in html


class InMemoryHandler(CrackerjackRequestHandler):
    """In-memory test harness capturing responses without opening TCP sockets."""
    def __init__(self, path: str = ""):
        self.path = path
        self.headers = {}
        self.last_status = None
        self.last_data = None
        self.response_headers = {}
        self.wfile = BytesIO()

    def send_response(self, status: int) -> None:
        self.last_status = status

    def send_header(self, key: str, value: str) -> None:
        self.response_headers[key] = value

    def end_headers(self) -> None:
        pass

    def _send_cors_headers(self) -> None:
        pass

    def _send_json_response(self, status: int, data: Any) -> None:
        self.last_status = status
        self.last_data = data


def test_handler_validate_endpoint():
    handler = InMemoryHandler()

    # Valid password
    handler._handle_validate({"password": "Correct-Horse-Battery-2026!", "check_breach": False})
    assert handler.last_status == HTTPStatus.OK
    assert handler.last_data["allowed"] is True
    assert handler.last_data["grade"] in ("A+", "A")
    assert len(handler.last_data["violations"]) == 0

    # Context match failure
    handler._handle_validate({"password": "AcmeCompanySecret123!", "context": ["acme"], "check_breach": False})
    assert handler.last_status == HTTPStatus.OK
    assert handler.last_data["allowed"] is False
    assert any("context-specific" in v.lower() for v in handler.last_data["violations"])


def test_handler_evaluate_endpoint():
    handler = InMemoryHandler()

    handler._handle_evaluate({"password": "Correct-Horse-Battery-2026!", "check_breach": False})
    assert handler.last_status == HTTPStatus.OK
    assert "nist" in handler.last_data
    assert handler.last_data["nist"]["score"] >= 80


def test_handler_generate_endpoint():
    handler = InMemoryHandler()

    handler._handle_generate({"words": 5, "separator": "_", "add_number": False})
    assert handler.last_status == HTTPStatus.OK
    assert "passphrase" in handler.last_data
    assert len(handler.last_data["passphrase"].split("_")) == 5
    assert handler.last_data["entropy_bits"] > 50.0
 
 
def test_root_serves_landing_page():
    handler = InMemoryHandler(path="/")
    handler.do_GET()
    assert handler.last_status == HTTPStatus.OK
    assert handler.response_headers.get("Content-Type") == "text/html; charset=utf-8"
    body = handler.wfile.getvalue().decode("utf-8")
    assert "Security built into" in body
    assert "every system layer" in body
    assert "https://d8j0ntlcm91z4.cloudfront.net" in body


def test_docs_route():
    handler = InMemoryHandler(path="/docs")
    handler.do_GET()
    assert handler.last_status == HTTPStatus.OK
    assert handler.response_headers.get("Content-Type") == "text/html; charset=utf-8"
    body = handler.wfile.getvalue().decode("utf-8")
    assert "SwaggerUIBundle" in body

