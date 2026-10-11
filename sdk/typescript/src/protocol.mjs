/**
 * protocol.mjs — the XCP wire primitives, ported from the contract.
 *
 * WHAT THIS IS A PORT OF
 * ----------------------
 * `sdk/contract/descriptor.json` describes the protocol surface and
 * `sdk/vectors/*.json` carry 142 input/output cases for the pure functions
 * every SDK must reproduce. Both are generated from the Python implementation
 * the conformance suite certifies. This file implements those functions in
 * JavaScript, and `vectors.mjs` proves it agrees.
 *
 * It is written against the vectors rather than against the Python source, on
 * purpose: a port written by reading the reference tends to reproduce the
 * reference's accidents along with its intent, and this project already has
 * one independent implementation (core/gateway-ts) precisely so the
 * conformance suite cannot encode the reference.
 *
 * THE ONE FUNCTION MOST LIKELY TO BE PORTED WRONGLY
 * -------------------------------------------------
 * `stripOws`. RFC 9110 5.5 defines OWS as exactly `*( SP / HTAB )`, and the
 * obvious JavaScript for "strip whitespace" is `String.prototype.trim()` --
 * which also removes LF, CR, VT, FF, NBSP, the BOM, the Ogham space mark, the
 * en quad, the narrow no-break space, the ideographic space and more.
 *
 * Using trim() here would be a security-relevant bug, not a cosmetic one. The
 * footprint in field three is compared byte-for-byte against a registered
 * session binding. A gateway that strips U+00A0 matches a binding that a
 * gateway implementing the RFC as written does not, so the same bytes
 * authenticate on one node and 401 on another -- intermittently, and with
 * nothing in either log mentioning whitespace. That exact class of bug has
 * already happened in this project between its Python and Node gateways, over
 * a trailing space, and was found by differential analysis rather than by
 * either test suite.
 *
 * So OWS is a two-character set, implemented by hand, and the vectors include
 * eleven codepoints where a host trim() would disagree. A port that reaches
 * for trim() fails them. That is the vectors' entire purpose.
 */

/** RFC 9110 5.5: OWS = *( SP / HTAB ). Nothing else. */
const OWS = new Set([" ", "\t"]);

export const HEADER = "xcp-agent-identity";
export const SEP = ";";
export const FIELDS = 3;

export const REASON_MALFORMED = "missing or malformed XCP-Agent-Identity";
export const REASON_NON_CANONICAL =
  "identity fields must be canonical decimal integers";

/**
 * Remove leading and trailing OWS — space and horizontal tab only.
 *
 * Deliberately not `trim()`. See the file header.
 */
export function stripOws(value) {
  if (typeof value !== "string") return "";
  let start = 0;
  let end = value.length;
  while (start < end && OWS.has(value[start])) start += 1;
  while (end > start && OWS.has(value[end - 1])) end -= 1;
  return value.slice(start, end);
}

/**
 * True when every character is an ASCII digit and there is at least one.
 *
 * Not `Number.isInteger(Number(s))`, and not a regex over `\d`. `Number("")`
 * is 0, `Number(" 1")` is 1, `Number("+1")` is 1, and in JavaScript `\d` is
 * ASCII-only but `\p{Nd}` is not — so a Devanagari digit would pass a
 * Unicode-aware check and then mean something different to a parser that
 * used `isdigit()`. Python's `str.isdigit()` accepts some non-ASCII digits
 * too, which is why the vectors pin the behaviour rather than the method.
 */
function isCanonicalDecimal(s) {
  if (s.length === 0) return false;
  for (let i = 0; i < s.length; i += 1) {
    const c = s.charCodeAt(i);
    if (c < 0x30 || c > 0x39) return false;
  }
  return true;
}

/**
 * Parse XCP-Agent-Identity.
 *
 * Returns `{ ok: true, agentId, chainId, footprint }` or
 * `{ ok: false, reason }`. Non-throwing because the gateway records every
 * refusal with its reason, and an exception would make the reason a stack
 * trace.
 *
 * `agentId` and `chainId` are BigInt. The vectors include a 40-digit agent id,
 * which exceeds Number.MAX_SAFE_INTEGER: parsing that as a Number would
 * silently round it, and two agents whose ids differ only beyond the 53rd bit
 * would become the same agent. That is the kind of thing a port gets wrong
 * once and never finds.
 */
export function parseAgentIdentity(header) {
  const parts = stripOws(header == null ? "" : String(header)).split(SEP);

  if (parts.length !== FIELDS) {
    return { ok: false, reason: REASON_MALFORMED };
  }
  if (!isCanonicalDecimal(parts[0]) || !isCanonicalDecimal(parts[1])) {
    return { ok: false, reason: REASON_NON_CANONICAL };
  }
  // The footprint is taken verbatim: not lowercased, not 0X-normalised, not
  // length-checked. Normalising would make two distinct headers select the
  // same binding, which is the differential this module exists to prevent.
  return {
    ok: true,
    agentId: BigInt(parts[0]),
    chainId: BigInt(parts[1]),
    footprint: parts[2],
  };
}

/**
 * Build the header, refusing to emit what the parser would refuse to read.
 *
 * A formatter that happily emits "+42001" ships a bug to whoever runs it
 * against a stricter peer. Note this check is deliberately BROADER than
 * stripOws: the parser removes only OWS because the RFC obliges it to, but
 * nothing obliges a formatter to emit a footprint padded with an ideographic
 * space.
 */
export function formatAgentIdentity(agentId, chainId, footprint) {
  const a = BigInt(agentId);
  const c = BigInt(chainId);
  if (a < 0n || c < 0n) throw new Error(REASON_NON_CANONICAL);
  const fp = String(footprint);
  if (fp.includes(SEP) || fp !== fp.trim()) {
    throw new Error(
      "footprint may not contain the field separator or surrounding " +
        "whitespace; it is compared byte-for-byte against a binding",
    );
  }
  const header = `${a}${SEP}${c}${SEP}${fp}`;
  const round = parseAgentIdentity(header);
  if (!round.ok) throw new Error(round.reason);
  return header;
}

/**
 * Derive an XCP scope from the mandatory MCP 2026-07-28 routing headers.
 *
 * Total by design: an unrecognised method still yields a scope string, so an
 * unknown call is denied by default rather than allowed because no rule
 * matched it.
 *
 * Two behaviours look like bugs and are not — do not "fix" either:
 *
 *   1. The method is NOT lowercased. "TOOLS/CALL" yields "mcp:TOOLS/CALL",
 *      which no `mcp:tools/*` mandate matches, so an uppercase method is
 *      refused. Normalising it would turn a refusal into an allow.
 *   2. The NAME is stripped here, while bindDigest refuses a non-canonical
 *      name outright. The asymmetry is deliberate on the binding side and
 *      tracked as a defect on this side; reproduce both as given.
 */
export function scopeFor(mcpMethod, mcpName = "") {
  const method = String(mcpMethod ?? "").trim();
  const name = String(mcpName ?? "").trim();
  if (!method) return "mcp:unknown/";

  const slash = method.indexOf("/");
  const family = slash === -1 ? method : method.slice(0, slash);
  const verb = slash === -1 ? "" : method.slice(slash + 1);

  if (method === "tools/call" && name) return `mcp:tools/${name}`;
  if (method === "prompts/get" && name) return `mcp:prompts/${name}`;
  if (["tools", "resources", "prompts", "completion", "tasks"].includes(family)) {
    return `mcp:${family}/${verb || "unknown"}`;
  }
  return `mcp:${family || "unknown"}/${verb || "unknown"}`;
}

// ── tier arithmetic ───────────────────────────────────────────────────────

// The `x` is REQUIRED. An earlier version of this port wrote `x?`, which
// accepted "A2H2" -- a spelling the Python implementation refuses. The vectors
// caught it. Left as a comment because "the separator is optional" is a
// plausible-looking convenience that would have let a TypeScript client send a
// tier the gateway rejects, and the next person to touch this regex should know
// it was already tried.
const CELL = /^a([0-2])xh([0-2])$/;

/**
 * Canonical form of a lattice cell: "A2xH2", with a LOWERCASE x.
 *
 * The trap: `cell.toUpperCase()` produces "A2XH2", which is not the canonical
 * form and will not match the lattice. Accepts case variants on input and
 * emits exactly one spelling.
 */
export function canonicalTier(cell) {
  const raw = String(cell ?? "").trim().toLowerCase();
  const m = CELL.exec(raw);
  if (!m) throw new Error(`not a lattice cell: ${JSON.stringify(cell)}`);
  return `A${m[1]}xH${m[2]}`;
}

export function parseTier(cell) {
  const c = canonicalTier(cell);
  return [Number(c[1]), Number(c[4])];
}

export function formatTier(agent, human) {
  return `A${agent}xH${human}`;
}

/**
 * Narrow an asserted tier against a ceiling, per leg, with min().
 *
 * Authority narrows at a boundary and never widens. The two legs are
 * independent: asserting A1xH1 against a ceiling of A2xH0 yields A1xH0, not
 * "whichever cell is lower overall" — there is no total order on the lattice
 * and treating it as if there were is how a port grants H1 where the ceiling
 * said H0.
 */
export function narrowTier(asserted, ceiling) {
  const [aa, ah] = parseTier(asserted);
  const [ca, ch] = parseTier(ceiling);
  return formatTier(Math.min(aa, ca), Math.min(ah, ch));
}

/**
 * True when `asserted` would grant more than `effective` on either leg.
 *
 * The guard that refuses a ticket granting more than the origin held. Mirrors
 * the predicate guarding the OAuth bridge.
 */
export function widens(asserted, effective) {
  const [aa, ah] = parseTier(asserted);
  const [ea, eh] = parseTier(effective);
  return aa < ea || ah < eh;
}

// ── version negotiation ───────────────────────────────────────────────────

export const SUPPORTED = ["0.1", "0.2"];
export const CURRENT = "0.2";
export const MINIMUM = "0.1";

function versionKey(v) {
  return String(v).trim().split("-")[0].split(".").map(Number);
}

function compareVersions(a, b) {
  const ka = versionKey(a);
  const kb = versionKey(b);
  for (let i = 0; i < Math.max(ka.length, kb.length); i += 1) {
    const x = ka[i] ?? 0;
    const y = kb[i] ?? 0;
    if (x !== y) return x - y;
  }
  return 0;
}

export function parseAccept(header) {
  return String(header ?? "")
    .split(",")
    .map((p) => p.trim())
    .filter((p) => p.length > 0);
}

/**
 * Pick the highest version both sides accept.
 *
 * A caller that advertises nothing gets the OLDEST version this build speaks,
 * not the newest. Assuming a silent peer is current is optimistic in the
 * direction that breaks things: a field that changed meaning would be read
 * under the wrong interpretation with no error.
 *
 * Throws when there is no common version, rather than guessing.
 */
export function negotiate(clientAccepts, serverSupports = SUPPORTED) {
  const accepts = (clientAccepts ?? []).filter(Boolean);
  let common;
  if (accepts.length === 0) {
    common = serverSupports.includes(MINIMUM)
      ? [MINIMUM]
      : serverSupports.slice(0, 1);
  } else {
    const supported = new Set(serverSupports);
    common = accepts.filter((v) => supported.has(v));
  }
  if (common.length === 0) {
    throw new Error(
      `no common protocol version: caller accepts ` +
        `${JSON.stringify([...accepts].sort())}, this implementation ` +
        `supports ${JSON.stringify([...serverSupports].sort())}`,
    );
  }
  const chosen = common.reduce((a, b) => (compareVersions(a, b) >= 0 ? a : b));
  return {
    version: chosen,
    downgraded: compareVersions(chosen, CURRENT) < 0,
  };
}

export function requestHeaders(accepts = SUPPORTED) {
  return {
    "XCP-Version": CURRENT,
    "XCP-Accept-Versions": accepts.join(","),
  };
}
