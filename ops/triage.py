"""
ops.triage — the first five minutes, automated.

A runbook that says "check whether the crypto fast path is enabled" is a runbook
nobody follows at 3am. This does the checks instead, against a live node, and
orders the output by what would hurt most.

    xcp triage https://gateway.example

Each finding carries a severity, what it means, and the next action — because a
diagnostic that reports a symptom without a remedy has moved the problem rather
than solved it.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Optional


class Sev(IntEnum):
    CRITICAL = 0    # traffic is being mishandled right now
    HIGH = 1        # a control is off or degraded
    MEDIUM = 2      # will hurt under load or over time
    INFO = 3        # worth knowing
    OK = 4

    @property
    def label(self) -> str:
        return ["CRIT", "HIGH", "MED ", "info", "ok  "][int(self)]


@dataclass
class Finding:
    sev: Sev
    check: str
    detail: str
    action: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"severity": self.sev.name, "check": self.check,
                "detail": self.detail, "action": self.action}

    def line(self) -> str:
        s = f"  {self.sev.label}  {self.check:<28}{self.detail}"
        if self.action and self.sev < Sev.INFO:
            s += f"\n        -> {self.action}"
        return s


def _get(url: str, timeout: float = 6) -> tuple[int, Any]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read())
        except Exception:
            return e.code, {}
    except Exception as e:
        return 0, {"_error": f"{type(e).__name__}: {e}"}


def triage(base: str) -> list[Finding]:
    """Diagnose a running node. Ordered worst-first."""
    base = base.rstrip("/")
    out: list[Finding] = []

    status, h = _get(f"{base}/health")
    if status != 200 or not h.get("ok"):
        out.append(Finding(
            Sev.CRITICAL, "reachability",
            f"/health returned {status or h.get('_error', 'no response')}",
            "The node is down or unreachable. Check the process, then the "
            "listener, then the network path — in that order."))
        return out
    out.append(Finding(Sev.OK, "reachability", f"healthy, gateway={h.get('gateway')}"))

    # ── posture: the single most consequential setting ──
    posture = h.get("posture")
    if posture == "observe":
        out.append(Finding(
            Sev.CRITICAL, "enforcement posture",
            "running in OBSERVE — calls are logged but NOT blocked",
            "Observe is for onboarding an endpoint you have not vetted, not a "
            "steady state. If this is production, set XCP_POSTURE=enforce now."))
    else:
        out.append(Finding(Sev.OK, "enforcement posture", "enforce"))

    # ── abuse controls: an unmetered public node is an open relay ──
    rl = h.get("rateLimit")
    if rl == "disabled" or rl is None:
        out.append(Finding(
            Sev.CRITICAL, "abuse controls",
            "rate limiting is DISABLED",
            "A node routing for callers it has never met, with no limit, is an "
            "open relay. Unset XCP_RATE_LIMIT=0 unless this is a private "
            "deployment behind another limiter."))
    else:
        rej = (rl or {}).get("rejections", {})
        tracked = (rl or {}).get("trackedCallers", 0)
        cap = (rl or {}).get("maxTracked", 1)
        out.append(Finding(Sev.OK, "abuse controls",
                           f"active, {tracked} callers tracked, rejections={rej or 'none'}"))
        if rej.get("global", 0) > 0:
            out.append(Finding(
                Sev.HIGH, "global ceiling",
                f"{rej['global']} requests rejected at the node-wide ceiling",
                "The node itself is saturated, not one caller. Scale out or "
                "raise XCP_GLOBAL_RATE — but confirm the load is legitimate "
                "first."))
        if tracked >= cap * 0.9:
            out.append(Finding(
                Sev.MEDIUM, "limiter memory",
                f"tracking {tracked}/{cap} callers — near the LRU cap",
                "Usually means identity rotation, which is what the cap exists "
                "to survive. Worth checking whether it is an attack."))

    # ── the 35x footgun ──
    if h.get("cryptoFastPath") is False:
        out.append(Finding(
            Sev.HIGH, "crypto backend",
            f"{h.get('cryptoBackend')} is pure Python — ~35x slower per call",
            "Signature verification runs on every request. `pip install "
            "coincurve` and restart; expect verify to drop from ~6.5ms to "
            "~0.19ms."))
    else:
        out.append(Finding(Sev.OK, "crypto backend",
                           f"{h.get('cryptoBackend')} (native)"))

    # ── telemetry ──
    tel = h.get("telemetry") or {}
    if tel.get("enabled"):
        if tel.get("detail") == "full":
            out.append(Finding(
                Sev.HIGH, "telemetry detail",
                "exporting at FULL detail — raw agent ids, scopes and hostnames",
                "Only appropriate for a self-hosted collector. If this ships to "
                "a third-party vendor it is a new processor and probably an "
                "international transfer. Set XCP_OTEL_DETAIL=scrubbed."))
        elif not tel.get("endpoint"):
            out.append(Finding(
                Sev.MEDIUM, "telemetry",
                "enabled but no OTLP endpoint — spans go to the console",
                "Set OTEL_EXPORTER_OTLP_ENDPOINT, or disable with XCP_OTEL=0 "
                "so the node is not doing work nobody collects."))
        else:
            out.append(Finding(Sev.OK, "telemetry",
                               f"exporting to {tel['endpoint']} ({tel['detail']})"))
        if tel.get("error"):
            out.append(Finding(
                Sev.MEDIUM, "telemetry init", f"failed: {tel['error']}",
                "The node is fine; you are flying without instruments."))
    else:
        out.append(Finding(Sev.OK, "telemetry",
                           "disabled (optional; node unaffected)"))

    # ── verifier and upstreams ──
    if h.get("verifier") in (None, "", "unset"):
        out.append(Finding(
            Sev.MEDIUM, "verifier", "no external verifier configured",
            "In-memory bindings only. Fine for a single node; a federation "
            "needs a shared or on-chain registry."))
    ups = h.get("upstreams") or {}
    if not ups:
        out.append(Finding(Sev.MEDIUM, "upstreams", "none configured",
                           "Every a2t call will 404. Set XCP_UPSTREAMS."))
    else:
        out.append(Finding(Sev.OK, "upstreams", f"{len(ups)} configured"))

    # ── federation ──
    fstatus, fed = _get(f"{base}/v1/federation/peers")
    if fstatus == 404:
        out.append(Finding(Sev.OK, "federation",
                           "not configured (standalone — valid)"))
    elif fstatus == 200:
        summary = fed.get("summary", {})
        n = summary.get("direct", 0)
        out.append(Finding(Sev.OK, "federation",
                           f"{n} direct peer(s), {summary.get('transitive',0)} introduced"))
        if summary.get("revoked", 0):
            out.append(Finding(
                Sev.HIGH, "revoked peers",
                f"{summary['revoked']} peer(s) revoked",
                "Confirm the revocation was yours. If a peer revoked itself, "
                "check whether you routed anything through it recently."))
        nstatus, rec = _get(f"{base}/.well-known/xcp-node.json")
        if nstatus == 200 and not rec.get("bindings"):
            out.append(Finding(
                Sev.HIGH, "node identity",
                "no signed certificate binding",
                "This identity cannot survive a certificate renewal — every "
                "peer will see a stranger. Run scripts/rotate-cert.py."))
    else:
        out.append(Finding(Sev.MEDIUM, "federation",
                           f"peers endpoint returned {fstatus}"))

    # ── protocol version ──
    if not h.get("protocolVersions"):
        out.append(Finding(
            Sev.HIGH, "protocol version",
            "the node advertises no version",
            "Peers cannot negotiate and will refuse to federate."))
    else:
        out.append(Finding(Sev.OK, "protocol version",
                           f"{h.get('protocolCurrent')} "
                           f"(supports {','.join(h['protocolVersions'])})"))

    dep = h.get("deprecations") or []
    expiring = [d for d in dep if d.get("removeAfter", "") < "2027-01-01"]
    if expiring:
        out.append(Finding(
            Sev.MEDIUM, "deprecations",
            f"{len(expiring)} removal date(s) inside a year",
            "Migrate before the date, or peers on newer builds stop "
            "understanding you."))

    # ── anonymous calls must be refused ──
    req = urllib.request.Request(
        f"{base}/v1/a2t/call",
        data=json.dumps({"server": "x", "tool": "y", "arguments": {}}).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=6) as r:
            code = r.status
    except urllib.error.HTTPError as e:
        code = e.code
    except Exception:
        code = 0
    if code in (200, 204):
        out.append(Finding(
            Sev.CRITICAL, "anonymous access",
            "an unauthenticated call was ACCEPTED",
            "This node is routing for anyone. Check posture and the session "
            "registry immediately."))
    elif code in (401, 403, 429):
        out.append(Finding(Sev.OK, "anonymous access", f"refused ({code})"))

    return sorted(out, key=lambda f: f.sev)


def worst(findings: list[Finding]) -> Sev:
    """
    The worst ACTIONABLE severity. INFO is context, not a problem — folding it
    into the verdict would mean a correctly configured node never reports clean,
    which trains an operator to ignore the exit code.
    """
    sev = min((f.sev for f in findings), default=Sev.OK)
    return Sev.OK if sev is Sev.INFO else sev


def report(base: str, findings: list[Finding]) -> str:
    lines = [f"Triage — {base}",
             time.strftime("  %Y-%m-%d %H:%M:%S UTC", time.gmtime()), ""]
    lines += [f.line() for f in findings]
    w = worst(findings)
    lines += ["", f"  worst severity: {w.name}"]
    if w <= Sev.HIGH:
        lines.append("  See docs/runbook.md for the matching playbook.")
    return "\n".join(lines)


__all__ = ["triage", "report", "worst", "Finding", "Sev"]
