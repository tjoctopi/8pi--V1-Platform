"""Endpoint discovery helpers — turn machine-readable specs into attack surface.

An OpenAPI/Swagger document is a *complete* inventory of an API's endpoints,
methods, and parameters — the single richest source of injection points for an
API target. :func:`parse_openapi` walks a Swagger 2.0 or OpenAPI 3.x document and
extracts ``(path, method, params)`` operations, expanding OpenAPI path templates
(``/users/{id}``) into concrete query-parameter leads. Deterministic, no network.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

#: Common locations an API serves its spec at (checked in order).
OPENAPI_PATHS: tuple[str, ...] = (
    "/openapi.json", "/swagger.json", "/swagger/v1/swagger.json",
    "/v2/api-docs", "/v3/api-docs", "/api-docs", "/api/swagger.json",
    "/api/openapi.json", "/openapi.yaml", "/swagger.yaml",
)

_PATH_TEMPLATE = re.compile(r"\{([^}/]+)\}")
_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}


@dataclass
class ApiOperation:
    """One API operation extracted from a spec."""

    path: str
    method: str
    #: Query/path parameters that carry attacker-controllable input.
    params: list[str] = field(default_factory=list)


def parse_openapi(raw: bytes) -> list[ApiOperation]:
    """Extract operations from a Swagger 2.0 / OpenAPI 3.x JSON document.

    Returns an empty list for anything that isn't a parseable spec (so callers
    can attempt several candidate URLs cheaply). Path-template variables become
    parameters too — they are attacker-controlled input just like query params.
    """

    try:
        doc = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(doc, dict):
        return []
    paths = doc.get("paths")
    if not isinstance(paths, dict):
        return []

    base = _base_path(doc)
    ops: list[ApiOperation] = []
    for raw_path, item in paths.items():
        if not isinstance(raw_path, str) or not isinstance(item, dict):
            continue
        full = _join(base, raw_path)
        template_params = _PATH_TEMPLATE.findall(raw_path)
        # Parameters declared at the path-item level apply to every method.
        shared = _params_of(item.get("parameters"))
        for method, op in item.items():
            if method.lower() not in _HTTP_METHODS or not isinstance(op, dict):
                continue
            params = sorted(set(template_params) | shared | _params_of(op.get("parameters")))
            ops.append(ApiOperation(
                path=_PATH_TEMPLATE.sub(r"\1", full),  # /users/{id} → /users/id
                method=method.upper(), params=params,
            ))
    return ops


def _params_of(raw: object) -> set[str]:
    """Names of query/path parameters from a parameters[] array."""

    out: set[str] = set()
    if not isinstance(raw, list):
        return out
    for p in raw:
        if isinstance(p, dict) and p.get("in") in ("query", "path") and p.get("name"):
            out.add(str(p["name"]))
    return out


def _base_path(doc: dict[str, object]) -> str:
    # Swagger 2.0 uses basePath; OpenAPI 3 uses servers[].url (path component).
    base = doc.get("basePath")
    if isinstance(base, str) and base:
        return base
    servers = doc.get("servers")
    if isinstance(servers, list) and servers and isinstance(servers[0], dict):
        url = servers[0].get("url")
        if isinstance(url, str) and url.startswith("/"):
            return url
    return ""


def _join(base: str, path: str) -> str:
    if not base:
        return path if path.startswith("/") else "/" + path
    return "/" + f"{base}/{path}".replace("//", "/").lstrip("/")
