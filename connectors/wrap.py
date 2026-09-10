"""
connectors.wrap — turn a public API into a routable MCP server.

WHY THIS IS A THIRD KIND, NOT MORE `routable`
---------------------------------------------
There are thousands of publicly reachable REST APIs with machine-readable specs.
It is tempting to count them as routable, since they are demonstrably online.
They are not: an MCP agent cannot connect to `https://api.stripe.com/v1`. That
endpoint speaks REST, not MCP. Marking it routable would make the Trust Firewall
send agent traffic somewhere every call fails.

What is true is that XCP can *make* it routable, by generating an MCP server that
fronts it. So the catalog carries a third kind:

    routable    an MCP endpoint an agent can connect to right now
    wrappable   a public API with a spec — routable once XCP deploys a wrapper
    installable a package — routable once an operator runs it

A `wrappable` entry becomes `routable` at **the deploying operator's own URL**,
not the vendor's. That is the same federation property as everything else here:
XCP does not host the long tail, thousands of nodes each expose what they wrap.

WHAT THE GENERATOR DOES
-----------------------
Reads an OpenAPI 3.x document and emits an MCP server that:
  · exposes one MCP tool per API operation, named `<operationId>`
  · derives each tool's inputSchema from the operation's parameters and body
  · resolves credentials through `vault://` references, never inline
  · speaks MCP 2026-07-28: no session, `Mcp-Method` / `Mcp-Name` honoured
  · refuses to emit operations it cannot describe safely

It is a code generator, not a proxy: you get a readable file you can inspect,
edit and deploy. A generated wrapper you cannot read is a supply-chain problem
wearing a convenience costume.

Status: XCP and ERC-8004x are draft proposals.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

HTTP_METHODS = ("get", "post", "put", "patch", "delete")
# Operations we refuse to expose without an explicit opt-in.
DESTRUCTIVE = ("delete",)


class WrapError(Exception):
    pass


@dataclass
class Operation:
    """One API operation, normalised into something MCP can describe."""
    operation_id: str
    method: str
    path: str
    summary: str = ""
    parameters: list[dict] = field(default_factory=list)
    has_body: bool = False
    body_required: bool = False
    destructive: bool = False

    @property
    def tool_name(self) -> str:
        return self.operation_id

    def input_schema(self) -> dict[str, Any]:
        props: dict[str, Any] = {}
        required: list[str] = []
        for p in self.parameters:
            name = p.get("name")
            if not name:
                continue
            schema = p.get("schema") or {"type": "string"}
            props[name] = {
                "type": schema.get("type", "string"),
                "description": (p.get("description") or
                                f"{p.get('in','query')} parameter")[:180],
            }
            if p.get("required"):
                required.append(name)
        if self.has_body:
            props["body"] = {"type": "object",
                             "description": "JSON request body"}
            if self.body_required:
                required.append("body")
        return {"type": "object", "properties": props, "required": required}


@dataclass
class WrapSpec:
    """A public API, normalised and ready to generate from."""
    id: str
    title: str
    base_url: str
    version: str = ""
    description: str = ""
    docs_url: str = ""
    auth_scheme: str = "none"          # none | bearer | basic | apiKey | oauth2
    auth_location: str = ""            # header | query, for apiKey
    auth_name: str = ""                # header/query name, for apiKey
    operations: list[Operation] = field(default_factory=list)

    @property
    def secret_ref(self) -> str:
        return f"vault://env/apis/{self.id}#credential"

    def summary(self) -> dict[str, Any]:
        return {"id": self.id, "title": self.title, "baseUrl": self.base_url,
                "operations": len(self.operations), "auth": self.auth_scheme,
                "docs": self.docs_url}


# ── parsing ────────────────────────────────────────────────────────────────

def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9._-]+", "-", (text or "").lower()).strip("-")


def _safe_id(raw: str, method: str, path: str) -> str:
    """An operationId that is a valid, readable MCP tool name."""
    if raw:
        s = re.sub(r"[^A-Za-z0-9_]+", "_", raw).strip("_")
        if s:
            return s[:64]
    tail = re.sub(r"[^A-Za-z0-9]+", "_", path).strip("_")
    return f"{method}_{tail}"[:64]


def parse_openapi(doc: dict, api_id: str = "", docs_url: str = "",
                  include_destructive: bool = False,
                  max_operations: int = 400) -> WrapSpec:
    """
    Normalise an OpenAPI 3.x document. Raises on the shapes we cannot honestly
    wrap rather than emitting a server that will fail at runtime.
    """
    if not isinstance(doc, dict):
        raise WrapError("spec is not a mapping")
    if "openapi" not in doc and "swagger" not in doc:
        raise WrapError("not an OpenAPI/Swagger document")
    info = doc.get("info") or {}
    servers = doc.get("servers") or []
    base = ""
    for s in servers:
        u = str((s or {}).get("url", ""))
        if u.startswith("https://"):
            base = u.rstrip("/")
            break
    if not base:
        # Swagger 2.0 fallback
        host, scheme = doc.get("host"), (doc.get("schemes") or ["https"])[0]
        if host and scheme == "https":
            base = f"https://{host}{doc.get('basePath','')}".rstrip("/")
    if not base:
        raise WrapError("no https server URL in the spec — nothing to reach")

    schemes = ((doc.get("components") or {}).get("securitySchemes") or {})
    auth, loc, aname = "none", "", ""
    for _k, v in schemes.items():
        t = (v or {}).get("type", "")
        if t == "http":
            auth = "bearer" if (v.get("scheme") == "bearer") else "basic"
            break
        if t == "apiKey":
            auth, loc, aname = "apiKey", v.get("in", "header"), v.get("name", "")
            break
        if t in ("oauth2", "openIdConnect"):
            auth = "oauth2"
            break

    ops: list[Operation] = []
    for path, item in (doc.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        shared = [p for p in (item.get("parameters") or []) if isinstance(p, dict)]
        for method in HTTP_METHODS:
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            destructive = method in DESTRUCTIVE
            if destructive and not include_destructive:
                continue
            params = shared + [p for p in (op.get("parameters") or [])
                               if isinstance(p, dict)]
            body = op.get("requestBody") or {}
            ops.append(Operation(
                operation_id=_safe_id(op.get("operationId", ""), method, path),
                method=method, path=path,
                summary=(op.get("summary") or op.get("description") or "")[:180],
                parameters=params, has_body=bool(body),
                body_required=bool(body.get("required")),
                destructive=destructive))
            if len(ops) >= max_operations:
                break
        if len(ops) >= max_operations:
            break

    if not ops:
        raise WrapError("no usable operations found")

    # de-duplicate tool names, which OpenAPI does not guarantee are unique
    seen: dict[str, int] = {}
    for o in ops:
        n = o.operation_id
        if n in seen:
            seen[n] += 1
            o.operation_id = f"{n}_{seen[n]}"
        else:
            seen[n] = 0

    return WrapSpec(
        id=api_id or _slug(info.get("title", "api")),
        title=info.get("title", "API"), base_url=base,
        version=str(info.get("version", "")),
        description=(info.get("description") or "")[:400],
        docs_url=docs_url or ((info.get("contact") or {}).get("url", "")),
        auth_scheme=auth, auth_location=loc, auth_name=aname, operations=ops)


# ── generation ─────────────────────────────────────────────────────────────

TEMPLATE = '''"""
{title} — MCP server generated from an OpenAPI specification.

Generated by connectors.wrap. Read it before you deploy it: a generated wrapper
you cannot inspect is a supply-chain problem wearing a convenience costume.

  upstream : {base_url}
  auth     : {auth_scheme}
  tools    : {n_ops}
  docs     : {docs_url}

The upstream credential is resolved at runtime from
    {secret_ref}
and is never written to this file or to the catalog.

Run:
    pip install fastapi "uvicorn[standard]" httpx
    uvicorn {module}:app --port 9100

Then register it with your XCP gateway; it becomes ROUTABLE at *your* URL, not
the vendor's.
"""

from __future__ import annotations

import os
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

BASE_URL = "{base_url}"
AUTH_SCHEME = "{auth_scheme}"
AUTH_LOCATION = "{auth_location}"
AUTH_NAME = "{auth_name}"
SECRET_REF = "{secret_ref}"
REQUIRE_VERIFIED = os.getenv("REQUIRE_VERIFIED", "1") == "1"

app = FastAPI(title="{title} (MCP)", version="{version}")

TOOLS: dict[str, dict[str, Any]] = {tools_literal}


def _credential() -> str:
    """Resolve the upstream credential. Never inline, never logged."""
    try:
        import sys, pathlib
        sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
        from vault import Vault, SecretRef
        return Vault().resolve(SecretRef.parse(SECRET_REF)).reveal()
    except Exception:
        return os.getenv("UPSTREAM_CREDENTIAL", "")


def _auth_headers() -> dict[str, str]:
    cred = _credential()
    if not cred or AUTH_SCHEME == "none":
        return {{}}
    if AUTH_SCHEME == "bearer":
        return {{"Authorization": f"Bearer {{cred}}"}}
    if AUTH_SCHEME == "basic":
        import base64
        return {{"Authorization": "Basic " + base64.b64encode(
            f"{{cred}}:".encode()).decode()}}
    if AUTH_SCHEME == "apiKey" and AUTH_LOCATION == "header" and AUTH_NAME:
        return {{AUTH_NAME: cred}}
    return {{}}


def _identity(request: Request) -> dict[str, str]:
    hdr = request.headers.get("xcp-agent-identity", "")
    by = request.headers.get("xcp-verified-by", "")
    parts = hdr.split(";")
    if len(parts) == 3 and by:
        return {{"agentId": parts[0], "verifiedBy": by}}
    return {{}}


@app.post("/mcp")
async def mcp(request: Request) -> JSONResponse:
    try:
        msg = await request.json()
    except Exception:
        return JSONResponse({{"jsonrpc": "2.0", "id": None,
                             "error": {{"code": -32700, "message": "parse error"}}}})
    method = msg.get("method") or request.headers.get("mcp-method", "")
    mid = msg.get("id")

    if method == "tools/list":
        return JSONResponse({{"jsonrpc": "2.0", "id": mid, "result": {{
            "tools": [{{"name": n, "description": t["summary"],
                        "inputSchema": t["schema"]}} for n, t in TOOLS.items()]}}}})

    if method == "tools/call":
        ident = _identity(request)
        if REQUIRE_VERIFIED and not ident:
            return JSONResponse({{"jsonrpc": "2.0", "id": mid, "error": {{
                "code": -32001,
                "message": "XCP: unverified call. Route through an XCP gateway."}}}},
                status_code=401)
        params = msg.get("params") or {{}}
        name = params.get("name", "") or request.headers.get("mcp-name", "")
        spec = TOOLS.get(name)
        if spec is None:
            return JSONResponse({{"jsonrpc": "2.0", "id": mid, "error": {{
                "code": -32602, "message": f"unknown tool {{name!r}}"}}}})
        args = dict(params.get("arguments") or {{}})
        body = args.pop("body", None)
        path = spec["path"]
        query: dict[str, Any] = {{}}
        for k, v in args.items():
            token = "{{" + k + "}}"
            if token in path:
                path = path.replace(token, str(v))
            else:
                query[k] = v
        try:
            async with httpx.AsyncClient(timeout=30) as hc:
                r = await hc.request(spec["method"].upper(), BASE_URL + path,
                                     params=query or None, json=body,
                                     headers=_auth_headers())
            payload = r.json() if r.headers.get("content-type", "").startswith(
                "application/json") else {{"text": r.text[:20000]}}
        except Exception as e:
            return JSONResponse({{"jsonrpc": "2.0", "id": mid, "error": {{
                "code": -32603, "message": f"upstream error: {{type(e).__name__}}"}}}})
        return JSONResponse({{"jsonrpc": "2.0", "id": mid, "result": {{
            "content": [{{"type": "text", "text": _dump(payload)}}],
            "_xcp": {{"servedFor": ident.get("agentId"),
                     "upstream": BASE_URL, "status": r.status_code}}}}}})

    return JSONResponse({{"jsonrpc": "2.0", "id": mid, "error": {{
        "code": -32601, "message": f"method not found: {{method}}"}}}})


def _dump(obj: Any) -> str:
    import json as _json
    try:
        return _json.dumps(obj)[:40000]
    except Exception:
        return str(obj)[:40000]


@app.get("/health")
async def health() -> dict:
    return {{"ok": True, "upstream": BASE_URL, "tools": len(TOOLS),
            "requiresVerified": REQUIRE_VERIFIED}}
'''


def generate(spec: WrapSpec, module_name: str = "") -> str:
    """Emit a deployable MCP server for this API."""
    tools = {
        o.tool_name: {"method": o.method, "path": o.path,
                      "summary": o.summary or f"{o.method.upper()} {o.path}",
                      "schema": o.input_schema()}
        for o in spec.operations
    }
    return TEMPLATE.format(
        title=spec.title.replace('"', "'"), base_url=spec.base_url,
        auth_scheme=spec.auth_scheme, auth_location=spec.auth_location,
        auth_name=spec.auth_name, secret_ref=spec.secret_ref,
        version=spec.version or "0", docs_url=spec.docs_url or "-",
        n_ops=len(spec.operations),
        module=module_name or f"mcp_{_slug(spec.id).replace('-', '_')}",
        tools_literal=json.dumps(tools, indent=4, sort_keys=True))


def wrap_openapi(doc: dict, api_id: str = "", **kw: Any) -> tuple[WrapSpec, str]:
    spec = parse_openapi(doc, api_id=api_id, **kw)
    return spec, generate(spec)


__all__ = ["WrapSpec", "Operation", "parse_openapi", "generate", "wrap_openapi",
           "WrapError", "HTTP_METHODS", "DESTRUCTIVE"]
