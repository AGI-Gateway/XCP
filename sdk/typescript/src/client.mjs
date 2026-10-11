/**
 * client.mjs — call an XCP gateway.
 *
 * The protocol primitives live in `protocol.mjs` and are pinned by the shared
 * vectors. This file is the transport around them: session lifecycle, the
 * three interaction streams, and the one thing a hand-written client usually
 * gets wrong, which is backoff.
 *
 * WHY RETRY IS IN THE SDK AND NOT LEFT TO THE CALLER
 * --------------------------------------------------
 * XCP's conformance suite requires a 429 to carry Retry-After (XCP-SEC-002),
 * because the gateway's rate limiter is a token bucket and the caller cannot
 * guess the refill rate. A client that ignores that header and retries on its
 * own schedule converts a working backpressure signal into a thundering herd,
 * and it does so under exactly the load where the gateway least needs help.
 *
 * So honouring Retry-After is not a convenience here, it is the client's half
 * of a protocol the server already implements. The default is to honour it and
 * retry idempotent requests only.
 *
 * WHAT IS NOT RETRIED
 * -------------------
 * 401 and 403. A rejected session or a denied mandate is a decision, not a
 * transient fault, and retrying it produces an identical refusal plus a second
 * audit record implying the caller is probing. The only correct response to a
 * 403 is to obtain authority the gateway will accept, which no amount of
 * waiting provides.
 */

import {
  formatAgentIdentity,
  parseAgentIdentity,
  requestHeaders,
  scopeFor,
} from "./protocol.mjs";

export class XCPError extends Error {
  constructor(message, { status = 0, reason = "", retryAfter = null } = {}) {
    super(message);
    this.name = "XCPError";
    this.status = status;
    this.reason = reason;
    this.retryAfter = retryAfter;
  }
}

/** Status codes worth retrying. A decision is never one of them. */
const RETRYABLE = new Set([429, 502, 503, 504]);

/** Ceiling on how long Retry-After may park a request, in milliseconds. */
const MAX_RETRY_WAIT_MS = 30_000;

function parseRetryAfter(value) {
  if (!value) return null;
  const seconds = Number(value);
  if (Number.isFinite(seconds) && seconds >= 0) {
    return Math.min(seconds * 1000, MAX_RETRY_WAIT_MS);
  }
  const when = Date.parse(value);           // RFC 9110 also allows a date
  if (!Number.isNaN(when)) {
    return Math.min(Math.max(0, when - Date.now()), MAX_RETRY_WAIT_MS);
  }
  return null;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export class XCPClient {
  /**
   * @param {string} gatewayUrl
   * @param {{agentId: bigint|number|string, chainId?: bigint|number|string,
   *          footprint: string, tier?: string}} identity
   * @param {{fetch?: Function, retries?: number, timeoutMs?: number}} [options]
   */
  constructor(gatewayUrl, identity, options = {}) {
    this.gatewayUrl = String(gatewayUrl).replace(/\/+$/, "");
    this.identity = {
      agentId: BigInt(identity.agentId),
      chainId: BigInt(identity.chainId ?? 8453),
      footprint: identity.footprint,
      // The floor on purpose. A0xH0 is read-only and tightly metered, so a
      // client that never declares a tier is throttled early rather than
      // granted something it did not establish.
      tier: identity.tier ?? "A0xH0",
    };
    // Validated at construction, not at first use: a malformed footprint
    // should fail where it was supplied, not inside a request six frames down.
    this.identityHeader = formatAgentIdentity(
      this.identity.agentId, this.identity.chainId, this.identity.footprint);

    this.session = null;
    this._fetch = options.fetch ?? globalThis.fetch;
    this._retries = options.retries ?? 2;
    this._timeoutMs = options.timeoutMs ?? 15_000;
    if (typeof this._fetch !== "function") {
      throw new XCPError("no fetch available; pass options.fetch on Node < 18");
    }
  }

  _headers(mandate) {
    const h = {
      "Content-Type": "application/json",
      "XCP-Agent-Identity": this.identityHeader,
      ...requestHeaders(),
    };
    if (mandate) h["XCP-Mandate"] = JSON.stringify(mandate);
    return h;
  }

  async _post(path, body, { mandate = null, idempotent = true,
    mcpMethod = "", mcpName = "" } = {}) {
    const url = `${this.gatewayUrl}${path}`;
    const headers = this._headers(mandate);
    if (mcpMethod) {
      // The mandatory MCP 2026-07-28 routing headers. The gateway derives the
      // scope it gates on from these, NOT from the body -- so a client that
      // omits them is asking the gateway to authorise "mcp:unknown/", which is
      // denied by default.
      headers["Mcp-Method"] = mcpMethod;
      if (mcpName) headers["Mcp-Name"] = mcpName;
    }

    let attempt = 0;
    for (;;) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this._timeoutMs);
      let res;
      try {
        res = await this._fetch(url, {
          method: "POST",
          headers,
          body: JSON.stringify(body ?? {}),
          signal: controller.signal,
        });
      } finally {
        clearTimeout(timer);
      }

      if (res.ok) return res.json();

      const retryAfter = parseRetryAfter(res.headers.get("retry-after"));
      let reason = "";
      try {
        reason = (await res.json())?.error ?? "";
      } catch {
        reason = await res.text().catch(() => "");
      }

      if (res.status === 401) {
        throw new XCPError(`session rejected: ${reason}`,
          { status: 401, reason });
      }
      if (res.status === 403) {
        throw new XCPError(`mandate denied: ${reason}`,
          { status: 403, reason });
      }

      const canRetry = idempotent && RETRYABLE.has(res.status)
        && attempt < this._retries;
      if (!canRetry) {
        throw new XCPError(`gateway error ${res.status}: ${reason}`,
          { status: res.status, reason, retryAfter });
      }

      // Honour Retry-After when given, and fall back to exponential backoff
      // when not. The server's number always wins: it knows its refill rate
      // and the client does not.
      const wait = retryAfter ?? Math.min(2 ** attempt * 250, 4000);
      await sleep(wait);
      attempt += 1;
    }
  }

  /** Open a channel-bound session. */
  async connect() {
    const data = await this._post("/v1/session/open", {
      agentId: Number(this.identity.agentId),
      chainId: Number(this.identity.chainId),
      footprint: this.identity.footprint,
      tier: this.identity.tier,
    });
    this.session = {
      sessionId: data.sessionId ?? "",
      mandateRoot: data.mandateRoot ?? "",
      rails: data.rails ?? 0,
    };
    return this.session;
  }

  async close() {
    if (!this.session) return;
    try {
      await this._post("/v1/session/close", {});
    } catch {
      // A session the gateway has already expired is not an error worth
      // raising during teardown.
    }
    this.session = null;
  }

  /**
   * Agent -> Tool. Sends the MCP routing headers, so the scope the gateway
   * gates on is `mcp:tools/<tool>` and the caller can see that it will be.
   */
  async callTool(server, tool, args = {}, { mandate = null } = {}) {
    return this._post("/v1/a2t/call",
      { server, tool, arguments: args },
      { mandate, mcpMethod: "tools/call", mcpName: tool });
  }

  /**
   * Agent <-> Agent. With `destination`, the gateway mints a signed ticket and
   * carries it there, and the response includes the destination's OWN
   * decision -- which may admit the delegation at a narrower tier.
   *
   * Without it nothing is delivered: the response reports `authorized` and
   * `delivered: false`. Those are different claims and the caller must read
   * both; a client that surfaced only `authorized` would report success for a
   * delegation that never arrived.
   */
  async delegate(peerDid, task, { mandate = null, destination = "" } = {}) {
    const body = { peerDid, task };
    if (destination) body.destination = destination;
    // Not idempotent: a retry could mint a second ticket for the same task.
    return this._post("/v1/a2a/delegate", body,
      { mandate, idempotent: false, mcpMethod: "a2a/delegate" });
  }

  /** Tool -> Tool. Requires chain scope, which exists at A1xH1 and above. */
  async chainTools(src, dst, payload, { mandate = null } = {}) {
    return this._post("/v1/t2t/pipe", { src, dst, payload },
      { mandate, idempotent: false, mcpMethod: "t2t/chain" });
  }

  /** The scope the gateway will gate on for a given call, computed locally. */
  scopeForTool(tool) {
    return scopeFor("tools/call", tool);
  }

  /** Read a peer's node record. Public, so no session is needed. */
  static async nodeRecord(origin, { fetch: f = globalThis.fetch } = {}) {
    const res = await f(`${String(origin).replace(/\/+$/, "")}`
      + `/.well-known/xcp-node.json`);
    if (!res.ok) {
      throw new XCPError(`node record unavailable: ${res.status}`,
        { status: res.status });
    }
    return res.json();
  }
}

export { parseAgentIdentity, formatAgentIdentity, scopeFor };
