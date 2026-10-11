/**
 * vectors.mjs — hold this port to the committed contract.
 *
 * The TypeScript counterpart of `python -m sdk`. Reads the same JSON and makes
 * the same assertions, so "does this SDK agree with the protocol" has one
 * answer shaped the same way in both ecosystems.
 *
 *     node sdk/typescript/vectors.mjs
 *
 * Every expected value is read from the file. Nothing here re-derives an
 * expectation, because a runner that computes what it then checks is a runner
 * that can only ever agree with itself.
 */

import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  canonicalTier,
  formatAgentIdentity,
  narrowTier,
  negotiate,
  parseAccept,
  parseAgentIdentity,
  scopeFor,
  stripOws,
  widens,
} from "./src/protocol.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const VECTORS = join(HERE, "..", "vectors");
const CONTRACT = join(HERE, "..", "contract", "descriptor.json");

const failures = [];
let passed = 0;
const skipped = [];

function cmp(vector, caseName, field, expected, actual) {
  const e = JSON.stringify(expected);
  const a = JSON.stringify(actual);
  if (e === a) {
    passed += 1;
  } else {
    failures.push(`${vector} / ${caseName} / ${field}: expected ${e}, got ${a}`);
  }
}

function load(name) {
  return JSON.parse(readFileSync(join(VECTORS, name), "utf8"));
}

// ── identity header ───────────────────────────────────────────────────────

{
  const v = load("identity_header.json");
  for (const c of v.cases) {
    const got = parseAgentIdentity(c.header);
    cmp("identity_header", c.name, "ok", c.ok, got.ok);
    if (c.ok) {
      if (!got.ok) continue;
      // BigInt is compared as a decimal string: the vectors include a 40-digit
      // agent id, and JSON.stringify cannot serialise a BigInt at all.
      cmp("identity_header", c.name, "agentId",
        String(c.agentId), String(got.agentId));
      cmp("identity_header", c.name, "chainId",
        String(c.chainId), String(got.chainId));
      cmp("identity_header", c.name, "footprint", c.footprint, got.footprint);
    } else {
      cmp("identity_header", c.name, "reason", c.reason, got.reason ?? null);
    }
  }
}

// The property that catches a port using trim(). Asserted directly as well as
// through the vectors, so a failure says WHY rather than listing 22 cases.
{
  const nonOws = ["\n", "\r", "\v", "\f", "\u0085", " ", " ",
    " ", " ", "　", "﻿"];
  for (const ch of nonOws) {
    const padded = `x${ch}`;
    if (stripOws(padded) !== padded) {
      failures.push(
        `stripOws removed U+${ch.codePointAt(0).toString(16).padStart(4, "0")}, ` +
        `which is not OWS. RFC 9110 5.5 is SP and HTAB only -- this is the ` +
        `trim() bug the vectors exist to catch.`);
    } else {
      passed += 1;
    }
  }
  for (const ch of [" ", "\t"]) {
    if (stripOws(`${ch}x${ch}`) === "x") passed += 1;
    else failures.push(`stripOws failed to remove ${JSON.stringify(ch)}`);
  }
}

// The formatter must refuse what the parser refuses.
{
  const bad = [[-1n, 8453n, "0xab"], [1n, -1n, "0xab"], [1n, 1n, "0x;ab"],
    [1n, 1n, " 0xab"], [1n, 1n, "0xab "]];
  for (const [a, c, f] of bad) {
    let threw = false;
    try { formatAgentIdentity(a, c, f); } catch { threw = true; }
    if (threw) passed += 1;
    else failures.push(`formatAgentIdentity emitted ${a};${c};${JSON.stringify(f)}`);
  }
}

// ── scope ─────────────────────────────────────────────────────────────────

{
  const v = load("scope.json");
  for (const c of v.cases) {
    cmp("scope", `${JSON.stringify(c.mcpMethod)}+${JSON.stringify(c.mcpName)}`,
      "scope", c.scope, scopeFor(c.mcpMethod, c.mcpName));
  }
}

// ── tier arithmetic ───────────────────────────────────────────────────────

{
  const v = load("tier.json");
  for (const c of v.canonicalTier) {
    let ok = true;
    let got = null;
    try { got = canonicalTier(c.input); } catch { ok = false; }
    cmp("tier", `canonical ${JSON.stringify(c.input)}`, "ok", c.ok, ok);
    cmp("tier", `canonical ${JSON.stringify(c.input)}`, "canonical",
      c.canonical, got);
  }
  for (const c of v.narrowTier) {
    let ok = true;
    let got = null;
    try { got = narrowTier(c.asserted, c.ceiling); } catch { ok = false; }
    cmp("tier", `narrow ${c.asserted}->${c.ceiling}`, "ok", c.ok, ok);
    cmp("tier", `narrow ${c.asserted}->${c.ceiling}`, "effective",
      c.effective, got);
  }
  for (const c of v.widens) {
    cmp("tier", `widens ${c.asserted}/${c.effective}`, "widens",
      c.widens, widens(c.asserted, c.effective));
  }
}

// ── version negotiation ───────────────────────────────────────────────────

{
  const v = load("negotiate.json");
  for (const c of v.cases) {
    cmp("negotiate", c.name, "parsed", c.parsed, parseAccept(c.acceptHeader));
    let ok = true;
    let version = null;
    let downgraded = null;
    try {
      const n = negotiate(parseAccept(c.acceptHeader), v.supported);
      version = n.version;
      downgraded = n.downgraded;
    } catch { ok = false; }
    cmp("negotiate", c.name, "ok", c.ok, ok);
    cmp("negotiate", c.name, "version", c.version, version);
    cmp("negotiate", c.name, "downgraded", c.downgraded, downgraded);
  }
}

// ── vectors this port does not implement ──────────────────────────────────

for (const name of readdirSync(VECTORS).sort()) {
  if (["identity_header.json", "scope.json", "tier.json", "negotiate.json"]
    .includes(name)) continue;
  const d = load(name);
  const n = Object.values(d).filter((x) => Array.isArray(x) && x[0]
    && typeof x[0] === "object").reduce((s, x) => s + x.length, 0);
  // Reported as a skip, never as a pass. bind_digest needs keccak256 and
  // lattice needs the envelope table; claiming agreement we did not verify is
  // the failure this harness exists to prevent.
  skipped.push(`${name} (${n} cases): not implemented in this port`);
}

// ── the descriptor's own claims ───────────────────────────────────────────

{
  const d = JSON.parse(readFileSync(CONTRACT, "utf8"));
  const ows = d.headers.identity.ows;
  if (JSON.stringify(ows) === JSON.stringify([" ", "\t"])) passed += 1;
  else failures.push(`descriptor OWS is ${JSON.stringify(ows)}, expected SP and HTAB`);
  if (d.protocol.current === "0.2") passed += 1;
  else failures.push(`descriptor current version is ${d.protocol.current}`);
}

// ── report ────────────────────────────────────────────────────────────────

console.log(`${passed} vectors reproduced, ${failures.length} disagreed`);
if (skipped.length) {
  console.log(`${skipped.length} skipped: ${skipped.join("; ")}`);
}
for (const f of failures) console.log(`  FAIL ${f}`);
process.exit(failures.length ? 1 : 0);
