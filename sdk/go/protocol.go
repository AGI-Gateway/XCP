// Package xcp implements the XCP wire primitives.
//
// WHAT THIS IS A PORT OF
//
// sdk/contract/descriptor.json describes the protocol surface and
// sdk/vectors/*.json carry input/output cases for the pure functions every XCP
// SDK must reproduce. Both are generated from the Python implementation the
// conformance suite certifies. protocol_test.go runs this package against them.
//
// THREE GO-SPECIFIC TRAPS, ALL OF THEM CAUGHT BY THE VECTORS
//
// 1. strings.TrimSpace is wrong for OWS. RFC 9110 5.5 defines OWS as exactly
// *( SP / HTAB ), while TrimSpace removes everything unicode.IsSpace accepts --
// NEL, NBSP, the Ogham space mark, the ideographic space and more. That matters
// because the footprint in field three is compared byte-for-byte against a
// registered session binding: a gateway that strips U+00A0 matches a binding
// that an RFC-faithful gateway does not, so identical bytes authenticate on one
// node and 401 on another, intermittently, with nothing in either log about
// whitespace. This project has already shipped that bug once, between its
// Python and Node gateways, over a trailing space.
//
// 2. strconv.Atoi is wrong for the integer fields. It accepts "+42001" and
// "-1", which differ from what a parser using an is-digit check reads from the
// same bytes. The fields must be canonical decimal digits, so the check is
// written by hand.
//
// 3. uint64 is too small for an agent id. Agent ids are uint256 on chain, and
// the vectors include a 40-digit value. Parsing into uint64 would overflow, and
// two agents differing only in the high bits would become the same agent. These
// are math/big.Int.
//
// Each trap is the obvious idiomatic choice. That is precisely why the vectors
// exist rather than a prose specification.
package xcp

import (
	"fmt"
	"math/big"
	"regexp"
	"strings"
)

const (
	// Header is the field name. Lower case because HTTP field names are
	// case-insensitive and every server in this project normalises them so.
	Header = "xcp-agent-identity"
	// Sep is the field separator: a semicolon rather than a comma, so the
	// value survives intermediaries that recombine repeated headers.
	Sep = ";"
	// Fields is the exact count. Not a minimum: a fourth field is a header
	// some other implementation understands and this one does not, which is
	// the point at which to stop rather than guess.
	Fields = 3

	ReasonMalformed    = "missing or malformed XCP-Agent-Identity"
	ReasonNonCanonical = "identity fields must be canonical decimal integers"
)

// StripOWS removes leading and trailing OWS: space and horizontal tab only.
//
// Deliberately not strings.TrimSpace. See the package documentation.
func StripOWS(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

// isCanonicalDecimal reports whether every byte is an ASCII digit, and there is
// at least one. Byte-wise rather than rune-wise: a Devanagari digit is a digit
// to unicode.IsDigit and is not what another parser in the chain will read.
func isCanonicalDecimal(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// AgentIdentity is the three fields of the header, after parsing. It carries no
// session state and performs no verification: whether a footprint matches a
// binding is a question for the session registry, not the parser.
type AgentIdentity struct {
	AgentID   *big.Int
	ChainID   *big.Int
	Footprint string
}

// String renders the canonical form. Parse(x.String()) == x for every x.
func (a AgentIdentity) String() string {
	return fmt.Sprintf("%s%s%s%s%s", a.AgentID.String(), Sep,
		a.ChainID.String(), Sep, a.Footprint)
}

// ParseAgentIdentity parses the header, returning the reason on failure.
//
// Returns the reason as a value rather than an error string built at the call
// site, because the gateway records every refusal with its reason and the
// reasons must match across implementations for the vectors to pin them.
func ParseAgentIdentity(header string) (AgentIdentity, string) {
	parts := strings.Split(StripOWS(header), Sep)
	if len(parts) != Fields {
		return AgentIdentity{}, ReasonMalformed
	}
	if !isCanonicalDecimal(parts[0]) || !isCanonicalDecimal(parts[1]) {
		return AgentIdentity{}, ReasonNonCanonical
	}
	agent, ok := new(big.Int).SetString(parts[0], 10)
	if !ok {
		return AgentIdentity{}, ReasonNonCanonical
	}
	chain, ok := new(big.Int).SetString(parts[1], 10)
	if !ok {
		return AgentIdentity{}, ReasonNonCanonical
	}
	// The footprint is taken verbatim: not lowercased, not 0X-normalised, not
	// length-checked. Normalising would make two distinct headers select the
	// same binding, which is the differential this package exists to prevent.
	return AgentIdentity{AgentID: agent, ChainID: chain,
		Footprint: parts[2]}, ""
}

// FormatAgentIdentity builds the header, refusing to emit what ParseAgentIdentity
// would refuse to read.
//
// The footprint check is deliberately broader than StripOWS: the parser removes
// only OWS because the RFC obliges it to, but nothing obliges a formatter to
// emit a footprint padded with an ideographic space. Be liberal only where the
// specification requires it, and strict in what you send.
func FormatAgentIdentity(agentID, chainID *big.Int, footprint string) (string, error) {
	if agentID == nil || chainID == nil {
		return "", fmt.Errorf("%s", ReasonNonCanonical)
	}
	if agentID.Sign() < 0 || chainID.Sign() < 0 {
		return "", fmt.Errorf("%s", ReasonNonCanonical)
	}
	if strings.Contains(footprint, Sep) ||
		strings.TrimSpace(footprint) != footprint {
		return "", fmt.Errorf("footprint may not contain the field separator " +
			"or surrounding whitespace; it is compared byte-for-byte against " +
			"a binding")
	}
	h := AgentIdentity{AgentID: agentID, ChainID: chainID,
		Footprint: footprint}.String()
	if _, reason := ParseAgentIdentity(h); reason != "" {
		return "", fmt.Errorf("%s", reason)
	}
	return h, nil
}

// ScopeFor derives an XCP scope from the mandatory MCP 2026-07-28 routing
// headers, with no reference to the request body.
//
// Total by design: an unrecognised method still yields a scope string, so an
// unknown call is denied by default rather than allowed because no rule matched.
//
// Two behaviours look like bugs and are not. The method is NOT lowercased, so
// "TOOLS/CALL" yields "mcp:TOOLS/CALL", which no mcp:tools/* mandate matches --
// normalising it would turn a refusal into an allow. And the NAME is trimmed
// here while BindDigest refuses a non-canonical name outright; reproduce both
// as given rather than making them agree.
func ScopeFor(mcpMethod, mcpName string) string {
	method := strings.TrimSpace(mcpMethod)
	name := strings.TrimSpace(mcpName)
	if method == "" {
		return "mcp:unknown/"
	}
	family, verb := method, ""
	if i := strings.Index(method, "/"); i >= 0 {
		family, verb = method[:i], method[i+1:]
	}
	if method == "tools/call" && name != "" {
		return "mcp:tools/" + name
	}
	if method == "prompts/get" && name != "" {
		return "mcp:prompts/" + name
	}
	switch family {
	case "tools", "resources", "prompts", "completion", "tasks":
		if verb == "" {
			verb = "unknown"
		}
		return "mcp:" + family + "/" + verb
	}
	if family == "" {
		family = "unknown"
	}
	if verb == "" {
		verb = "unknown"
	}
	return "mcp:" + family + "/" + verb
}

// cellPattern requires the x. An earlier port made it optional, which accepted
// "A2H2" -- a spelling the reference refuses. The vectors caught it.
var cellPattern = regexp.MustCompile(`^a([0-2])xh([0-2])$`)

// CanonicalTier returns the canonical spelling of a lattice cell: "A2xH2", with
// a LOWERCASE x.
//
// The trap is strings.ToUpper, which produces "A2XH2" -- not the canonical form
// and no match for the lattice. Case variants are accepted on input and exactly
// one spelling is emitted.
func CanonicalTier(cell string) (string, error) {
	m := cellPattern.FindStringSubmatch(
		strings.ToLower(strings.TrimSpace(cell)))
	if m == nil {
		return "", fmt.Errorf("not a lattice cell: %q", cell)
	}
	return "A" + m[1] + "xH" + m[2], nil
}

// ParseTier returns the agent and human legs of a cell.
func ParseTier(cell string) (int, int, error) {
	c, err := CanonicalTier(cell)
	if err != nil {
		return 0, 0, err
	}
	return int(c[1] - '0'), int(c[4] - '0'), nil
}

// FormatTier renders a cell from its two legs.
func FormatTier(agent, human int) string {
	return fmt.Sprintf("A%dxH%d", agent, human)
}

// NarrowTier narrows an asserted tier against a ceiling, per leg, with min.
//
// Authority narrows at a boundary and never widens. The legs are independent:
// A1xH1 against a ceiling of A2xH0 yields A1xH0, not "whichever cell is lower
// overall". There is no total order on the lattice, and treating it as if there
// were is how a port grants H1 where the ceiling said H0.
func NarrowTier(asserted, ceiling string) (string, error) {
	aa, ah, err := ParseTier(asserted)
	if err != nil {
		return "", err
	}
	ca, ch, err := ParseTier(ceiling)
	if err != nil {
		return "", err
	}
	return FormatTier(min(aa, ca), min(ah, ch)), nil
}

// Widens reports whether asserted would grant more than effective on either
// leg. The guard that refuses a ticket granting more than the origin held.
func Widens(asserted, effective string) bool {
	aa, ah, err := ParseTier(asserted)
	if err != nil {
		return false
	}
	ea, eh, err := ParseTier(effective)
	if err != nil {
		return false
	}
	return aa < ea || ah < eh
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
