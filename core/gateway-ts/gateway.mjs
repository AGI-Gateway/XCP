#!/usr/bin/env node
/**
 * A second XCP gateway, in Node, written against the specification rather than
 * against the Python source.
 *
 * WHY THIS EXISTS
 * ---------------
 * The conformance suite was built to certify independent implementations and
 * had never faced one. A suite that only ever runs against the implementation
 * it was written alongside is not a specification instrument — it is a
 * regression test with ambitions. This is the control.
 *
 * It is deliberately written from `docs/protocol.md` and the conformance
 * clauses, not by porting Python. Where the two disagree, the disagreement is
 * the finding.
 *
 * Deliberately dependency-free (node:http only), so it can be run anywhere
 * Node exists and audited in one sitting.
 *
 *     node core/gateway-ts/gateway.mjs            # port 8080
 *     XCP_PORT=8099 node core/gateway-ts/gateway.mjs
 */
import { createServer } from "node:http";
import { createHash, timingSafeEqual } from "node:crypto";

const PORT = Number(process.env.XCP_PORT || 8080);
const POSTURE = process.env.XCP_POSTURE || "enforce";
const GATEWAY_ID = process.env.XCP_GATEWAY_ID || "gw-node";
const RATE_LIMIT = process.env.XCP_RATE_LIMIT !== "0";
const ADMIN_TOKEN = process.env.XCP_ADMIN_TOKEN || "";
const UPSTREAMS = JSON.parse(process.env.XCP_UPSTREAMS || "{}");

const PROTOCOL_VERSIONS = ["0.1", "0.2"];
const PROTOCOL_CURRENT = "0.2";
const FEATURES = ["session", "mandate", "stateless", "limits"];

// ── session registry ───────────────────────────────────────────────────────
// Bindings are capped at seven days by the protocol, so expiry is not optional.
const bindings = new Map();           // footprint -> binding

function bind({ agentId, chainId, footprint, tier, mandateRoot, rails }) {
  const b = {
    agentId, chainId, footprint,
    tier: tier || "A0xH0",
    mandateRoot: mandateRoot || "0x" + "00".repeat(32),
    rails: rails ?? 0b0011,
    notAfter: Math.floor(Date.now() / 1000) + 7 * 86400,
    revoked: false,
  };
  bindings.set(footprint.toLowerCase(), b);
  return b;
}

function verify(footprint) {
  const b = bindings.get(String(footprint || "").toLowerCase());
  if (!b) return null;
  if (b.revoked) return null;
  if (b.notAfter < Math.floor(Date.now() / 1000)) return null;
  return b;
}

// ── abuse controls: capacity follows authority ─────────────────────────────
// Same lattice-keyed allowances as the reference. An anonymous caller gets the
// austere bucket because that is where abuse arrives.
const ALLOWANCES = {
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
const ANONYMOUS = { rate: 20, burst: 10, conc: 1, body: 32 * 1024 };
const COST = { "tools/list": 1, "tools/call": 5, "_default": 5 };

const buckets = new Map();
const MAX_TRACKED = 50000;            // a limiter keyed on caller input must be bounded

function allowanceFor(tier) { return ALLOWANCES[tier] || ANONYMOUS; }

function meter(key, tier, method, bodyBytes) {
  if (!RATE_LIMIT) return { allowed: true };
  const a = allowanceFor(tier);
  const cost = COST[method] ?? COST._default;
  if (bodyBytes > a.body) {
    return { allowed: false, limit: "body", retryAfter: 0,
             reason: `request body exceeds ${a.body} bytes for tier ${tier || "anonymous"}` };
  }
  const now = Date.now() / 1000;
  let b = buckets.get(key);
  if (!b) {
    if (buckets.size >= MAX_TRACKED) {
      // Evict oldest. Without this the limiter is itself a memory-exhaustion
      // vector, since the key comes from the caller.
      buckets.delete(buckets.keys().next().value);
    }
    b = { tokens: a.burst, updated: now };
    buckets.set(key, b);
  }
  b.tokens = Math.min(a.burst, b.tokens + (now - b.updated) * (a.rate / 60));
  b.updated = now;
  if (b.tokens < cost) {
    const retry = Math.max(1, Math.ceil((cost - b.tokens) / (a.rate / 60)));
    return { allowed: false, limit: "rate", retryAfter: retry,
             reason: `rate limit for tier ${tier || "anonymous"} (${a.rate}/min)` };
  }
  b.tokens -= cost;
  return { allowed: true };
}

// ── identity and mandate ───────────────────────────────────────────────────

function parseIdentity(header) {
  // XCP-Agent-Identity: <agentId>;<chainId>;<footprint>
  if (!header) return { ok: false, reason: "no identity header" };
  const parts = String(header).split(";");
  if (parts.length !== 3) return { ok: false, reason: "malformed identity header" };
  // Deliberately NOT trimmed. Normalising here lets this parser and an
  // upstream disagree about the same bytes, which is the differential the
  // binding digest exists to prevent.
  const [agentId, chainId, footprint] = parts;
  if (!/^\d+$/.test(agentId) || !/^\d+$/.test(chainId)) {
    return { ok: false, reason: "malformed identity header" };
  }
  // Anchored and case-fixed: an implementation that accepts "0X..." or a
  // footprint with surrounding whitespace will disagree with one that does
  // not, and both will believe they verified the same session.
  if (!/^0x[0-9a-f]{64}$/.test(footprint)) {
    return { ok: false, reason: "malformed certificate footprint" };
  }
  const binding = verify(footprint);
  if (!binding) return { ok: false, reason: "footprint is not bound to any session" };
  if (Number(agentId) !== binding.agentId) {
    return { ok: false, reason: "agent does not match the bound session" };
  }
  return { ok: true, agentId: Number(agentId), footprint, binding };
}

function scopeCovered(scopes, wanted) {
  return scopes.some((s) => {
    if (s === wanted) return true;
    if (s.endsWith("/*")) return wanted.startsWith(s.slice(0, -1));
    if (s.endsWith("*")) return wanted.startsWith(s.slice(0, -1));
    return false;
  });
}

function checkMandate(header, wantedScope) {
  if (!header) return { ok: false, reason: "no mandate presented" };
  let m;
  try { m = JSON.parse(header); }
  catch { return { ok: false, reason: "mandate is not valid JSON" }; }
  const notAfter = Number(m.notAfter || 0);
  if (!notAfter || notAfter < Math.floor(Date.now() / 1000)) {
    return { ok: false, reason: "mandate has expired" };
  }
  const scopes = Array.isArray(m.mandateScope) ? m.mandateScope : [];
  if (!scopeCovered(scopes, wantedScope)) {
    return { ok: false, reason: `mandate does not cover ${wantedScope}` };
  }
  return { ok: true, mandate: m };
}

// ── protocol version negotiation ───────────────────────────────────────────

function negotiate(acceptHeader) {
  const accepts = String(acceptHeader || "").split(",").map((s) => s.trim()).filter(Boolean);
  if (accepts.length === 0) {
    // A caller that says nothing gets the OLDEST version, not the newest.
    return { ok: true, version: PROTOCOL_VERSIONS[0] };
  }
  const common = accepts.filter((v) => PROTOCOL_VERSIONS.includes(v));
  if (common.length === 0) {
    return { ok: false, reason: `no common protocol version: caller accepts ` +
      `${JSON.stringify(accepts)}, this implementation supports ` +
      `${JSON.stringify(PROTOCOL_VERSIONS)}` };
  }
  common.sort();
  return { ok: true, version: common[common.length - 1] };
}

// ── helpers ────────────────────────────────────────────────────────────────

function send(res, status, obj, headers = {}) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { "Content-Type": "application/json", ...headers });
  res.end(body);
}

function adminOk(req) {
  if (!ADMIN_TOKEN) return false;      // unset means DISABLED, not open
  const h = String(req.headers["authorization"] || "");
  const presented = h.toLowerCase().startsWith("bearer ") ? h.slice(7) : "";
  const a = Buffer.from(presented), b = Buffer.from(ADMIN_TOKEN);
  return a.length === b.length && timingSafeEqual(a, b);
}

function readBody(req, cap) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on("data", (c) => {
      size += c.length;
      if (size > cap) { reject(new Error("body too large")); req.destroy(); return; }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function clientKey(req, binding) {
  if (binding) return `${binding.tier}|${binding.agentId}`;
  return `|${req.socket.remoteAddress || "anon"}`;
}

function audit(msg) {
  const t = new Date().toISOString().slice(11, 19);
  console.log(`[${t}] gw=${GATEWAY_ID} ${msg}`);
}

// ── routes ─────────────────────────────────────────────────────────────────

const server = createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const path = url.pathname;

  if (path === "/health" && req.method === "GET") {
    return send(res, 200, {
      ok: true, posture: POSTURE, gateway: GATEWAY_ID,
      implementation: "node",
      protocolVersions: PROTOCOL_VERSIONS, protocolCurrent: PROTOCOL_CURRENT,
      features: FEATURES,
      upstreams: Object.keys(UPSTREAMS),
      rateLimit: RATE_LIMIT
        ? { trackedCallers: buckets.size, maxTracked: MAX_TRACKED, failClosed: true }
        : "disabled",
    });
  }

  // Version negotiation runs before anything else. A caller this build cannot
  // talk to is refused with the list it does support, rather than being served
  // a response it may misread.
  const neg = negotiate(req.headers["xcp-accept-versions"]);
  if (!neg.ok) {
    return send(res, 400, { error: `XCP version negotiation failed: ${neg.reason}`,
                            supported: PROTOCOL_VERSIONS });
  }
  const vHeaders = { "XCP-Version": neg.version };

  if (path === "/v1/session/open" && req.method === "POST") {
    const m = meter(clientKey(req, null), "", "tools/list", 0);
    if (!m.allowed) {
      return send(res, 429, { error: `XCP rate limit: ${m.reason}`, limit: m.limit },
                  { "Retry-After": String(Math.max(1, m.retryAfter)), ...vHeaders });
    }
    let body;
    try { body = JSON.parse((await readBody(req, 64 * 1024)).toString() || "{}"); }
    catch { return send(res, 400, { error: "invalid request body" }, vHeaders); }
    if (!body.footprint || !body.agentId) {
      return send(res, 400, { error: "agentId and footprint are required" }, vHeaders);
    }
    const b = bind({
      agentId: Number(body.agentId), chainId: Number(body.chainId || 8453),
      footprint: String(body.footprint), tier: body.tier,
      mandateRoot: body.mandateRoot, rails: body.rails,
    });
    return send(res, 200, {
      sessionId: createHash("sha256").update(b.footprint).digest("hex").slice(0, 32),
      agentId: b.agentId, mandateRoot: b.mandateRoot, rails: b.rails,
      tier: b.tier, notAfter: b.notAfter,
    }, vHeaders);
  }

  if (path === "/v1/session/close" && req.method === "POST") {
    let body = {};
    try { body = JSON.parse((await readBody(req, 64 * 1024)).toString() || "{}"); } catch {}
    const b = bindings.get(String(body.footprint || "").toLowerCase());
    if (b) b.revoked = true;
    return send(res, 200, { closed: true }, vHeaders);
  }

  if (path === "/admin/revoke" && req.method === "POST") {
    if (!adminOk(req)) {
      audit("admin/revoke refused (no valid admin token)");
      return send(res, 401, {
        error: "administrative endpoints require a bearer token; set " +
               "XCP_ADMIN_TOKEN on the gateway" }, vHeaders);
    }
    let body = {};
    try { body = JSON.parse((await readBody(req, 64 * 1024)).toString() || "{}"); } catch {}
    const b = bindings.get(String(body.footprint || "").toLowerCase());
    if (b) b.revoked = true;
    return send(res, 200, { revoked: Boolean(b) }, vHeaders);
  }

  if ((path === "/v1/a2t/call" || path === "/v1/a2a/delegate" ||
       path === "/v1/t2t/pipe") && req.method === "POST") {
    const stream = path.split("/")[2];

    // Identity first, so the caller's tier decides their allowance. But the
    // limiter runs whether or not they are verified: rejecting with 401 still
    // costs a lookup, so an unauthenticated flood must be metered too.
    const ident = parseIdentity(req.headers["xcp-agent-identity"]);
    const tier = ident.ok ? ident.binding.tier : "";
    const key = clientKey(req, ident.ok ? ident.binding : null);
    const pre = meter(key, tier, "tools/call", 0);
    if (!pre.allowed) {
      return send(res, 429, { error: `XCP rate limit: ${pre.reason}`, limit: pre.limit },
                  { "Retry-After": String(Math.max(1, pre.retryAfter)), ...vHeaders });
    }

    if (!ident.ok && POSTURE === "enforce") {
      audit(`${stream} REJECT (${ident.reason})`);
      return send(res, 401, { error: `XCP: unverified call. ${ident.reason}. ` +
                                     `Route through an XCP gateway.` }, vHeaders);
    }

    const cap = allowanceFor(tier).body;
    let raw;
    try { raw = await readBody(req, cap); }
    catch {
      return send(res, 413, { error: `request body exceeds ${cap} bytes for ` +
                                     `tier ${tier || "anonymous"}` }, vHeaders);
    }
    let body;
    try { body = JSON.parse(raw.toString() || "{}"); }
    catch { return send(res, 400, { error: "invalid request body" }, vHeaders); }

    const tool = String(body.tool || "");
    const scope = stream === "a2t" ? `mcp:tools/${tool}`
                : stream === "a2a" ? `a2a:delegate/${body.peerDid || ""}`
                : `t2t:chain/${body.src || ""}->${body.dst || ""}`;

    const mand = checkMandate(req.headers["xcp-mandate"], scope);
    if (!mand.ok && POSTURE === "enforce") {
      audit(`${stream} BLOCKED ${scope} (${mand.reason})`);
      return send(res, 403, { error: "XCP: action not covered by the mandate",
                              reason: mand.reason, scope }, vHeaders);
    }

    const upstream = UPSTREAMS[body.server];
    if (!upstream) {
      return send(res, 404, { error: `no upstream configured for ` +
                                     `${JSON.stringify(body.server || null)}` }, vHeaders);
    }
    try {
      const r = await fetch(upstream, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Mcp-Method": "tools/call", "Mcp-Name": tool,
          "XCP-Verified-By": GATEWAY_ID,
          "XCP-Agent-Identity": String(ident.agentId ?? ""),
          "XCP-Trust-Tier": tier,
        },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call",
                               params: { name: tool, arguments: body.arguments || {} } }),
      });
      audit(`${stream} OK server=${body.server} tool=${tool}`);
      return send(res, 200, await r.json(), vHeaders);
    } catch (e) {
      return send(res, 502, { error: "upstream unavailable" }, vHeaders);
    }
  }

  return send(res, 404, { error: "no such endpoint" }, vHeaders);
});

server.listen(PORT, "127.0.0.1", () => {
  audit(`node gateway listening on 127.0.0.1:${PORT} posture=${POSTURE}`);
  if (!ADMIN_TOKEN) audit("/admin/* is DISABLED: set XCP_ADMIN_TOKEN to enable it.");
});
