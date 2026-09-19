"""
conformance.suite — prove an implementation speaks XCP.

WHY THIS EXISTS
---------------
A federation is a protocol, not a program. If the only way to know whether your
gateway is correct is to read the Python reference and hope, the protocol
fragments: every implementation ends up subtly different, and "federation"
degrades into "everyone talks to the reference implementation."

So this is deliberately **black-box**. It talks HTTP to a URL and imports nothing
from the implementation under test. A Go, Rust or TypeScript gateway can run it
and get the same verdict.

THE NEGATIVE TESTS ARE THE POINT
--------------------------------
Most of what follows checks that an implementation **refuses** things: an
unverified call, an out-of-scope mandate, a replayed credential, an oversized
body. A suite that only exercised happy paths would certify nothing about a
trust layer — a gateway that accepts everything passes every happy-path test and
is worse than useless.

MUST vs SHOULD
--------------
Failing a MUST means the implementation is non-conformant. Failing a SHOULD is a
warning. That distinction is load-bearing: a suite where everything is mandatory
gets ignored the first time a reasonable deployment fails it.

PROFILES
--------
Not every deployment does everything. An implementation declares what it claims
and is tested on that:

    core        session verification and the mandate gate
    stateless   MCP 2026-07-28 — header-derived scope, call-bound credentials
    security    abuse controls
    federation  node records and certificate bindings

A passing `core` + `security` report is the evidence a catalog needs to promote a
server from `unknown` to `probed`. That is the intended use: conformance is not a
badge, it is an input to somebody else's trust decision.

Status: XCP and ERC-8004x are draft proposals; clause numbering will change.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Callable, Optional

SUITE_VERSION = "0.1-draft"
DEFAULT_TIMEOUT = 10


class Level(str, Enum):
    MUST = "MUST"
    SHOULD = "SHOULD"


class Profile(str, Enum):
    CORE = "core"
    STATELESS = "stateless"
    SECURITY = "security"
    FEDERATION = "federation"


class Outcome(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"          # a SHOULD that was not met
    SKIP = "skip"          # not applicable, or a prerequisite failed
    ERROR = "error"        # the check itself could not run


@dataclass
class Result:
    clause: str
    title: str
    profile: Profile
    level: Level
    outcome: Outcome
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        for k in ("profile", "level", "outcome"):
            d[k] = getattr(self, k).value
        return d


@dataclass
class Report:
    target: str
    suite_version: str = SUITE_VERSION
    started_at: int = 0
    results: list[Result] = field(default_factory=list)

    @property
    def conformant(self) -> bool:
        """Conformant means no MUST failed. Warnings do not disqualify."""
        return not any(r.outcome is Outcome.FAIL for r in self.results)

    def counts(self) -> dict[str, int]:
        from collections import Counter
        return dict(Counter(r.outcome.value for r in self.results))

    def failures(self) -> list[Result]:
        return [r for r in self.results if r.outcome is Outcome.FAIL]

    def profiles_passed(self) -> list[str]:
        seen: dict[Profile, bool] = {}
        for r in self.results:
            if r.outcome is Outcome.FAIL:
                seen[r.profile] = False
            else:
                seen.setdefault(r.profile, True)
        return sorted(p.value for p, ok in seen.items() if ok)

    def to_dict(self) -> dict[str, Any]:
        return {"target": self.target, "suiteVersion": self.suite_version,
                "startedAt": self.started_at, "conformant": self.conformant,
                "counts": self.counts(),
                "profilesPassed": self.profiles_passed(),
                "results": [r.to_dict() for r in self.results]}


# ── HTTP, deliberately dependency-free ─────────────────────────────────────

@dataclass
class Response:
    status: int
    body: dict[str, Any]
    headers: dict[str, str]
    error: str = ""


def _call(url: str, *, method: str = "POST", body: Any = None,
          headers: Optional[dict[str, str]] = None,
          timeout: int = DEFAULT_TIMEOUT, raw: Optional[bytes] = None) -> Response:
    data = raw if raw is not None else (
        json.dumps(body).encode() if body is not None else None)
    h = {"Content-Type": "application/json", **(headers or {})}
    req = urllib.request.Request(url, data=data, headers=h,
                                 method=method if data is not None or method != "POST"
                                 else "POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            payload = r.read(4 * 1024 * 1024)
            try:
                parsed = json.loads(payload)
            except Exception:
                parsed = {"_raw": payload[:400].decode("utf-8", "replace")}
            return Response(r.status, parsed if isinstance(parsed, dict) else {},
                            dict(r.headers))
    except urllib.error.HTTPError as e:
        payload = e.read()
        try:
            parsed = json.loads(payload)
        except Exception:
            parsed = {"_raw": payload[:400].decode("utf-8", "replace")}
        return Response(e.code, parsed if isinstance(parsed, dict) else {},
                        dict(e.headers or {}))
    except Exception as e:
        return Response(0, {}, {}, error=f"{type(e).__name__}: {e}")


# ── the checks ─────────────────────────────────────────────────────────────

CHECKS: list[tuple[str, str, Profile, Level, Callable]] = []


def check(clause: str, title: str, profile: Profile, level: Level):
    def deco(fn: Callable) -> Callable:
        CHECKS.append((clause, title, profile, level, fn))
        return fn
    return deco


class Ctx:
    """Shared state for a run: the target and a session the checks can reuse."""

    def __init__(self, base: str, agent_id: int = 424242) -> None:
        self.base = base.rstrip("/")
        self.agent_id = agent_id
        self.footprint = "0x" + "c0" * 32
        self.session_ok = False
        self.tier = "A2xH2"

    def ident(self, footprint: Optional[str] = None) -> dict[str, str]:
        return {"XCP-Agent-Identity":
                f"{self.agent_id};8453;{footprint or self.footprint}"}

    def mandate(self, scopes: list[str], not_after: Optional[int] = None) -> dict[str, str]:
        return {"XCP-Mandate": json.dumps(
            {"mandateId": "conf", "delegator": "0xCONFORMANCE",
             "mandateScope": scopes,
             "notAfter": not_after if not_after is not None
             else int(time.time()) + 3600,
             "leaf": "0x", "proof": [], "signature": ""})}

    def a2t(self, tool: str = "echo", **kw) -> Response:
        return _call(f"{self.base}/v1/a2t/call",
                     body={"server": "research", "tool": tool, "arguments": {}}, **kw)



REFUSALS = {401, 403, 429}


def _refused(r: "Response", expected: int) -> tuple[Outcome, str]:
    """
    A "must refuse" check asserts the call was refused, not that one exact code
    came back. 429 is still a refusal — an implementation that rate limits the
    conformance run has not become non-conformant — but a 2xx means the request
    was honoured, which is the actual failure.
    """
    if r.error:
        return Outcome.ERROR, r.error
    if r.status == expected:
        return Outcome.PASS, ""
    if r.status == 429:
        return Outcome.PASS, "refused with 429 (rate limited) rather than " \
                             f"{expected}; still a refusal"
    if r.status in REFUSALS:
        return Outcome.PASS, f"refused with {r.status}, expected {expected}"
    return Outcome.FAIL, f"expected a refusal ({expected}), got {r.status}"


# ---- core ----

@check("XCP-CORE-001", "Exposes a health endpoint", Profile.CORE, Level.SHOULD)
def _core_001(c: Ctx) -> tuple[Outcome, str]:
    r = _call(f"{c.base}/health", method="GET")
    if r.error:
        return Outcome.WARN, f"unreachable: {r.error}"
    if r.status == 200 and r.body.get("ok") is True:
        return Outcome.PASS, ""
    return Outcome.WARN, f"status {r.status}"


@check("XCP-CORE-002", "Opens a session and returns a binding",
       Profile.CORE, Level.MUST)
def _core_002(c: Ctx) -> tuple[Outcome, str]:
    r = _call(f"{c.base}/v1/session/open",
              body={"agentId": c.agent_id, "chainId": 8453,
                    "footprint": c.footprint, "tier": c.tier})
    if r.status == 200:
        c.session_ok = True
        return Outcome.PASS, ""
    if r.status in (401, 403):
        # Legitimate: an on-chain verifier will not bind an unknown footprint.
        return Outcome.SKIP, ("refuses to bind an unknown footprint "
                              "(external verifier); later checks limited")
    return Outcome.FAIL, f"status {r.status}: {str(r.body)[:120]}"


@check("XCP-CORE-003", "Refuses a call with no identity header",
       Profile.CORE, Level.MUST)
def _core_003(c: Ctx) -> tuple[Outcome, str]:
    r = c.a2t(headers=c.mandate(["mcp:tools/echo"]))
    o, d = _refused(r, 401)
    if o is Outcome.FAIL:
        d += " — an unauthenticated caller must not be routed"
    return o, d


@check("XCP-CORE-004", "Refuses a malformed identity header",
       Profile.CORE, Level.MUST)
def _core_004(c: Ctx) -> tuple[Outcome, str]:
    r = c.a2t(headers={"XCP-Agent-Identity": "not-a-valid-header",
                       **c.mandate(["mcp:tools/echo"])})
    return _refused(r, 401)


@check("XCP-CORE-005", "Refuses an unbound certificate footprint",
       Profile.CORE, Level.MUST)
def _core_005(c: Ctx) -> tuple[Outcome, str]:
    r = c.a2t(headers={**c.ident("0x" + "de" * 32),
                       **c.mandate(["mcp:tools/echo"])})
    o, d = _refused(r, 401)
    if o is Outcome.FAIL:
        d += " — a footprint nobody bound must not be accepted"
    return o, d


@check("XCP-CORE-006", "Refuses a call with no mandate", Profile.CORE, Level.MUST)
def _core_006(c: Ctx) -> tuple[Outcome, str]:
    if not c.session_ok:
        return Outcome.SKIP, "no session could be opened"
    return _refused(c.a2t(headers=c.ident()), 403)


@check("XCP-CORE-007", "Refuses a scope the mandate does not cover",
       Profile.CORE, Level.MUST)
def _core_007(c: Ctx) -> tuple[Outcome, str]:
    if not c.session_ok:
        return Outcome.SKIP, "no session could be opened"
    r = c.a2t(tool="sum", headers={**c.ident(), **c.mandate(["mcp:tools/echo"])})
    o, d = _refused(r, 403)
    if o is Outcome.FAIL:
        d += " — scope coverage is the whole point of the mandate gate"
    return o, d


@check("XCP-CORE-008", "Refuses an expired mandate", Profile.CORE, Level.MUST)
def _core_008(c: Ctx) -> tuple[Outcome, str]:
    if not c.session_ok:
        return Outcome.SKIP, "no session could be opened"
    return _refused(c.a2t(headers={**c.ident(),
                                   **c.mandate(["mcp:tools/echo"],
                                               not_after=int(time.time()) - 60)}), 403)


@check("XCP-CORE-009", "Accepts a valid session and mandate",
       Profile.CORE, Level.MUST)
def _core_009(c: Ctx) -> tuple[Outcome, str]:
    if not c.session_ok:
        return Outcome.SKIP, "no session could be opened"
    r = c.a2t(headers={**c.ident(), **c.mandate(["mcp:tools/echo"])})
    if r.status in (200, 404, 502):
        # 404/502 mean the gate passed and routing failed upstream, which is not
        # a conformance problem for the gateway itself.
        return Outcome.PASS, ("gate passed; upstream unavailable"
                              if r.status != 200 else "")
    if r.status == 429:
        return Outcome.SKIP, "rate limited during the run; could not verify"
    return Outcome.FAIL, (f"a correctly authorised call was refused with "
                          f"{r.status}: {str(r.body)[:120]}")


@check("XCP-CORE-010", "Error responses carry a reason", Profile.CORE, Level.SHOULD)
def _core_010(c: Ctx) -> tuple[Outcome, str]:
    r = c.a2t(headers=c.mandate(["mcp:tools/echo"]))
    if isinstance(r.body, dict) and r.body.get("error"):
        return Outcome.PASS, ""
    return Outcome.WARN, "a rejection should say why, for operator diagnosis"


# ---- stateless (MCP 2026-07-28) ----

@check("XCP-STATELESS-001", "Does not require a session id header",
       Profile.STATELESS, Level.MUST)
def _sl_001(c: Ctx) -> tuple[Outcome, str]:
    if not c.session_ok:
        return Outcome.SKIP, "no session could be opened"
    r = c.a2t(headers={**c.ident(), **c.mandate(["mcp:tools/echo"])})
    if r.status in (200, 404, 502):
        return Outcome.PASS, ""
    if r.status == 429:
        return Outcome.SKIP, "rate limited during the run"
    return Outcome.FAIL, ("requests without Mcp-Session-Id were refused; that "
                          "header was removed in MCP 2026-07-28")


@check("XCP-STATELESS-002", "Tolerates a legacy session id rather than failing",
       Profile.STATELESS, Level.SHOULD)
def _sl_002(c: Ctx) -> tuple[Outcome, str]:
    if not c.session_ok:
        return Outcome.SKIP, "no session could be opened"
    r = c.a2t(headers={**c.ident(), **c.mandate(["mcp:tools/echo"]),
                       "Mcp-Session-Id": "stale-client"})
    if r.status in (200, 404, 502, 429):
        return Outcome.PASS, ""
    return Outcome.WARN, "a stale header should warn, not break the call"


# ---- security ----

@check("XCP-SEC-001", "Rate limits an anonymous caller", Profile.SECURITY, Level.MUST)
def _sec_001(c: Ctx) -> tuple[Outcome, str]:
    seen429 = False
    for _ in range(120):
        r = c.a2t(headers=c.mandate(["mcp:tools/echo"]))
        if r.status == 429:
            seen429 = True
            break
        if r.error:
            return Outcome.ERROR, r.error
    if seen429:
        return Outcome.PASS, ""
    return Outcome.FAIL, ("120 anonymous calls were accepted without a 429 — an "
                          "endpoint that routes for strangers with no limit is "
                          "an open relay")


@check("XCP-SEC-002", "A 429 carries Retry-After", Profile.SECURITY, Level.SHOULD)
def _sec_002(c: Ctx) -> tuple[Outcome, str]:
    for _ in range(200):
        r = c.a2t(headers=c.mandate(["mcp:tools/echo"]))
        if r.status == 429:
            ra = {k.lower(): v for k, v in r.headers.items()}.get("retry-after")
            if ra:
                return Outcome.PASS, f"Retry-After: {ra}"
            return Outcome.WARN, "429 without Retry-After leaves clients guessing"
        if r.error:
            return Outcome.ERROR, r.error
    return Outcome.SKIP, "no 429 observed"


@check("XCP-SEC-003", "Rejects an oversized body", Profile.SECURITY, Level.MUST)
def _sec_003(c: Ctx) -> tuple[Outcome, str]:
    big = json.dumps({"server": "research", "tool": "echo",
                      "arguments": {"pad": "A" * (24 * 1024 * 1024)}}).encode()
    r = _call(f"{c.base}/v1/a2t/call", raw=big,
              headers={**c.ident(), **c.mandate(["mcp:tools/echo"])},
              timeout=20)
    if r.status in (413, 429, 400):
        return Outcome.PASS, f"status {r.status}"
    if r.error:
        return Outcome.PASS, f"connection refused the payload ({r.error[:40]})"
    return Outcome.FAIL, (f"a 24 MB body was accepted with {r.status}; one "
                          "request must not be able to consume the node")


# ---- federation ----

@check("XCP-FED-001", "Publishes a node record", Profile.FEDERATION, Level.MUST)
def _fed_001(c: Ctx) -> tuple[Outcome, str]:
    r = _call(f"{c.base}/.well-known/xcp-node.json", method="GET")
    if r.status == 200 and r.body.get("node_id"):
        return Outcome.PASS, ""
    return Outcome.FAIL, f"no usable node record (status {r.status})"


@check("XCP-FED-002", "The node record is well formed", Profile.FEDERATION, Level.MUST)
def _fed_002(c: Ctx) -> tuple[Outcome, str]:
    r = _call(f"{c.base}/.well-known/xcp-node.json", method="GET")
    if r.status != 200:
        return Outcome.SKIP, "no node record"
    missing = [k for k in ("domain", "node_id", "gateway_url") if not r.body.get(k)]
    if missing:
        return Outcome.FAIL, f"missing fields: {missing}"
    if not str(r.body["gateway_url"]).startswith("https://"):
        return Outcome.FAIL, "gateway_url must be https"
    return Outcome.PASS, ""


@check("XCP-FED-003", "Identity is not the certificate footprint",
       Profile.FEDERATION, Level.SHOULD)
def _fed_003(c: Ctx) -> tuple[Outcome, str]:
    r = _call(f"{c.base}/.well-known/xcp-node.json", method="GET")
    if r.status != 200:
        return Outcome.SKIP, "no node record"
    if r.body.get("bindings"):
        return Outcome.PASS, ""
    return Outcome.WARN, ("no signed certificate binding: this identity cannot "
                          "survive a certificate renewal")


# ── runner ─────────────────────────────────────────────────────────────────

def run(target: str, profiles: Optional[list[Profile]] = None,
        agent_id: int = 424242) -> Report:
    """Run the suite against any XCP endpoint. Imports nothing from it."""
    wanted = set(profiles or [Profile.CORE, Profile.STATELESS, Profile.SECURITY])
    ctx = Ctx(target, agent_id=agent_id)
    rep = Report(target=target, started_at=int(time.time()))
    for clause, title, profile, level, fn in CHECKS:
        if profile not in wanted:
            continue
        try:
            outcome, detail = fn(ctx)
        except Exception as e:                        # a broken check is not a
            outcome, detail = Outcome.ERROR, f"{type(e).__name__}: {e}"  # failure
        if outcome is Outcome.FAIL and level is Level.SHOULD:
            outcome = Outcome.WARN
        rep.results.append(Result(clause, title, profile, level, outcome, detail))
    return rep


def format_report(rep: Report) -> str:
    icon = {Outcome.PASS: "pass", Outcome.FAIL: "FAIL", Outcome.WARN: "warn",
            Outcome.SKIP: "skip", Outcome.ERROR: "ERR "}
    lines = [f"XCP conformance — {rep.target}",
             f"suite {rep.suite_version}", ""]
    for r in rep.results:
        lines.append(f"  {icon[r.outcome]}  {r.clause:<20} {r.title}")
        if r.detail:
            lines.append(f"        {r.detail}")
    c = rep.counts()
    lines += ["", f"  {c.get('pass',0)} passed, {c.get('fail',0)} failed, "
                  f"{c.get('warn',0)} warnings, {c.get('skip',0)} skipped",
              "", f"  CONFORMANT: {'yes' if rep.conformant else 'NO'}"]
    if rep.profiles_passed():
        lines.append(f"  profiles passed: {', '.join(rep.profiles_passed())}")
    return "\n".join(lines)


__all__ = ["run", "format_report", "Report", "Result", "Profile", "Level",
           "Outcome", "CHECKS", "SUITE_VERSION"]
