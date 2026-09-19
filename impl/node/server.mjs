/**
 * An independent XCP gateway.
 *
 * Written against the conformance clauses, not by porting the Python. The
 * value of a second implementation is entirely in the places where it
 * disagrees — a specification with one implementation is a description of that
 * implementation.
 *
 * Implements: core, security. Federation/receipts are deliberately absent
 * rather than stubbed, because a stub that returns success is worse than an
 * honest 501.
 */
import { createServer } from "node:http";
import { createHash, timingSafeEqual } from "node:crypto";

const PORT = Number(process.env.PORT || 8080);
const POSTURE = process.env.XCP_POSTURE || "enforce";
const RATE_LIMIT = process.env.XCP_RATE_LIMIT !== "0";
const ADMIN_TOKEN = process.env.XCP_ADMIN_TOKEN || "";
const PROTOCOL_VERSIONS = ["0.1", "0.2"];

// ── trust lattice: capacity follows authority ──────────────────────────────
const ALLOWANCE = {
  "A0xH0": { rate: 60, burst: 30, conc: 2, body: 64 * 1024 },
  "A0xH1": { rate: 300, burst: 150, conc: 4, body: 256 * 1024 },
  "A0xH2": { rate: 120, burst: 60, conc: 2, body: 64 * 1024 },
  "A1xH0": { rate: 600, burst: 300, conc: 8, body: 1024 * 1024 },
  "A1xH1": { rate: 3000, burst: 1000, conc: 16, body: 4 * 1024 * 1024 },
  "A1xH2": { rate: 6000, burst: 2000, conc: 32, body: 8 * 1024 * 1024 },
  "A2xH0": { rate: 3000, burst: 1000, conc: 16, body: 4 * 1024 * 1024 },
  "A2xH1": { rate: 6000, burst: 2000, conc: 32, body: 8 * 1024 * 1024 },
  "A2xH2": { rate: 30000, burst: 10000, conc: 64, body: 16 * 1024 * 1024 },
};
const ANON = { rate: 20, burst: 10, conc: 1, body: 32 * 1024 };
const COST = { "tools/list": 1, "tools/call": 5, _default: 5 };

// Bounded: a limiter keyed on an attacker-supplied value is itself a memory
// exhaustion vector if it grows without limit.
const MAX_TRACKED = 50_000;
const buckets = new Map();

function allowanceFor(tier) { return ALLOWANCE[tier] || ANON; }

function meter(key, tier, method, bodyBytes) {
  if (!RATE_LIMIT) return null;
  const a = allowanceFor(tier);
  if (bodyBytes > a.body) return { limit: "body", retry: 0,
    reason: `request body exceeds ${a.body} bytes for tier ${tier || "anonymous"}` };
  const now = Date.now() / 1000;
  let b = buckets.get(key);
  if (!b) {
    if (buckets.size >= MAX_TRACKED) buckets.delete(buckets.keys().next().value);
    b = { tokens: a.burst, updated: now };
    buckets.set(key, b);
  }
  b.tokens = Math.min(a.burst, b.tokens + (now - b.updated) * (a.rate / 60));
  b.updated = now;
  const cost = COST[method] ?? COST._default;
  if (b.tokens < cost) {
    const retry = Math.max(1, Math.ceil((cost - b.tokens) / (a.rate / 60)));
    return { limit: "rate", retry,
             reason: `rate limit for tier ${tier || "anonymous"} (${a.rate}/min)` };
  }
  b.tokens -= cost;
  return null;
}

// ── sessions ───────────────────────────────────────────────────────────────
const sessions = new Map();   // footprint -> { agentId, tier, notAfter }

function parseIdentity(h) {
  const raw = h["xcp-agent-identity"];
  if (!raw) return { verified: false, reason: "no identity header" };
  const parts = String(raw).split(";");
  if (parts.length !== 3) return { verified: false, reason: "malformed identity header" };
  const [agentId, chainId, footprint] = parts;
  if (!/^\d+$/.test(agentId) || !/^0x[0-9a-fA-F]{64}$/.test(footprint))
    return { verified: false, reason: "malformed identity header" };
  const s = sessions.get(footprint.toLowerCase());
  if (!s) return { verified: false, reason: "footprint is not bound to any session" };
  if (s.notAfter < Date.now() / 1000)
    return { verified: false, reason: "session has expired" };
  return { verified: true, agentId: Number(agentId), tier: s.tier, footprint };
}

function checkMandate(h, scope) {
  const raw = h["xcp-mandate"];
  if (!raw) return "no mandate presented";
  let m;
  try { m = JSON.parse(raw); } catch { return "mandate is not valid JSON"; }
  if (!m.notAfter || Number(m.notAfter) < Date.now() / 1000)
    return "mandate has expired";
  const scopes = m.mandateScope || [];
  if (!scopes.some((s) => s === scope || (s.endsWith("*") && scope.startsWith(s.slice(0, -1)))))
    return `scope ${scope} is not covered by the mandate`;
  return null;
}

function adminOk(h) {
  if (!ADMIN_TOKEN) return false;
  const hdr = String(h.authorization || "");
  const got = hdr.toLowerCase().startsWith("bearer ") ? hdr.slice(7) : "";
  const a = Buffer.from(got), b = Buffer.from(ADMIN_TOKEN);
  return a.length === b.length && timingSafeEqual(a, b);
}

function negotiate(h) {
  const accept = String(h["xcp-accept-versions"] || "")
    .split(",").map((s) => s.trim()).filter(Boolean);
  if (!accept.length) return { ok: true, version: PROTOCOL_VERSIONS[0] };
  const common = accept.filter((v) => PROTOCOL_VERSIONS.includes(v));
  if (!common.length) return { ok: false };
  return { ok: true, version: common.sort().at(-1) };
}

// ── server ─────────────────────────────────────────────────────────────────
const json = (res, code, obj, extra = {}) => {
  res.writeHead(code, { "Content-Type": "application/json", ...extra });
  res.end(JSON.stringify(obj));
};

createServer((req, res) => {
  const chunks = [];
  let size = 0, aborted = false;
  req.on("data", (c) => {
    size += c.length;
    // Cap before buffering: reading an unbounded body to then reject it is a
    // memory exhaustion vector of its own.
    if (size > 24 * 1024 * 1024) { aborted = true; req.destroy(); return; }
    chunks.push(c);
  });
  req.on("end", () => {
    if (aborted) return;
    const raw = Buffer.concat(chunks);
    const h = req.headers;
    const url = req.url.split("?")[0];
    const ip = req.socket.remoteAddress || "anon";

    if (url === "/health") {
      return json(res, 200, {
        ok: true, posture: POSTURE, gateway: "xcp-node",
        protocolVersions: PROTOCOL_VERSIONS, protocolCurrent: "0.2",
        implementation: "node", rateLimit: RATE_LIMIT ? { active: true } : "disabled",
      });
    }

    const v = negotiate(h);
    if (!v.ok) return json(res, 400,
      { error: "XCP version negotiation failed", supported: PROTOCOL_VERSIONS });

    if (url === "/v1/session/open" && req.method === "POST") {
      const lim = meter(`anon:${ip}`, "", "tools/list", raw.length);
      if (lim) return json(res, 429, { error: `XCP rate limit: ${lim.reason}` },
                           { "Retry-After": String(lim.retry) });
      let b; try { b = JSON.parse(raw || "{}"); } catch { b = {}; }
      const fp = String(b.footprint || "").toLowerCase();
      if (!/^0x[0-9a-f]{64}$/.test(fp))
        return json(res, 400, { error: "a 32-byte footprint is required" });
      sessions.set(fp, { agentId: Number(b.agentId || 0),
                         tier: String(b.tier || "A0xH0"),
                         notAfter: Date.now() / 1000 + 7 * 86400 });
      return json(res, 200, { sessionId: createHash("sha256").update(fp).digest("hex").slice(0, 32),
                              tier: b.tier || "A0xH0" },
                  { "XCP-Version": v.version });
    }

    if (url === "/v1/a2t/call" && req.method === "POST") {
      const ident = parseIdentity(h);
      // Metered BEFORE authentication: rejecting with 401 still costs a lookup,
      // so an unauthenticated flood is a denial of service unless it is priced.
      const key = ident.verified ? `agent:${ident.agentId}` : `anon:${ip}`;
      const lim = meter(key, ident.verified ? ident.tier : "", "tools/call", raw.length);
      if (lim) return json(res, lim.limit === "body" ? 413 : 429,
        { error: `XCP rate limit: ${lim.reason}`, limit: lim.limit },
        lim.limit === "body" ? {} : { "Retry-After": String(lim.retry) });

      if (!ident.verified && POSTURE === "enforce")
        return json(res, 401, { error: `XCP: ${ident.reason}` });

      let b; try { b = JSON.parse(raw || "{}"); } catch { b = {}; }
      const scope = `mcp:tools/${b.tool || ""}`;
      const why = checkMandate(h, scope);
      if (why && POSTURE === "enforce")
        return json(res, 403, { error: `XCP: ${why}`, scope });

      return json(res, 502, { error: "no upstream configured in this implementation" },
                  { "XCP-Version": v.version });
    }

    if (url === "/admin/revoke" && req.method === "POST") {
      if (!adminOk(h)) return json(res, 401,
        { error: "administrative endpoints require a bearer token" });
      let b; try { b = JSON.parse(raw || "{}"); } catch { b = {}; }
      const had = sessions.delete(String(b.footprint || "").toLowerCase());
      return json(res, 200, { revoked: had, footprint: b.footprint });
    }

    json(res, 404, { error: "not found" });
  });
}).listen(PORT, "127.0.0.1", () =>
  console.log(`xcp-node listening on ${PORT} (posture=${POSTURE})`));
