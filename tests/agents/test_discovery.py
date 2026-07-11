"""OpenAPI/Swagger endpoint-discovery parser tests."""

from __future__ import annotations

import json

from attack_engine.agents.discovery import parse_openapi


def test_swagger_2_paths_and_query_params() -> None:
    doc = {
        "swagger": "2.0",
        "basePath": "/api/v1",
        "paths": {
            "/products/search": {
                "get": {"parameters": [
                    {"name": "q", "in": "query"},
                    {"name": "limit", "in": "query"},
                    {"name": "X-Trace", "in": "header"},  # not attacker-input surface
                ]}
            }
        },
    }
    ops = parse_openapi(json.dumps(doc).encode())
    assert len(ops) == 1
    op = ops[0]
    assert op.path == "/api/v1/products/search"
    assert op.method == "GET"
    assert set(op.params) == {"q", "limit"}  # header param excluded


def test_openapi_3_path_templates_become_params() -> None:
    doc = {
        "openapi": "3.0.0",
        "servers": [{"url": "/v3"}],
        "paths": {
            "/users/{id}": {
                "parameters": [{"name": "id", "in": "path"}],
                "get": {"parameters": [{"name": "expand", "in": "query"}]},
                "delete": {},
            }
        },
    }
    ops = parse_openapi(json.dumps(doc).encode())
    by_method = {o.method: o for o in ops}
    assert by_method["GET"].path == "/v3/users/id"
    assert set(by_method["GET"].params) == {"id", "expand"}
    assert set(by_method["DELETE"].params) == {"id"}


def test_non_spec_returns_empty() -> None:
    assert parse_openapi(b"<html>not a spec</html>") == []
    assert parse_openapi(b'{"just": "json", "no": "paths"}') == []
    assert parse_openapi(b"") == []
