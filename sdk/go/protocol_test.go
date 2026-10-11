// protocol_test.go — hold this port to the committed contract.
//
// The Go counterpart of `python -m sdk` and `node sdk/typescript/vectors.mjs`.
// Reads the same JSON and makes the same assertions, so "does this SDK agree
// with the protocol" has one answer shaped the same way in three ecosystems.
//
//	go test ./sdk/go/...
//
// Every expected value is read from the file. Nothing here re-derives an
// expectation: a runner that computes what it then checks can only ever agree
// with itself.
package xcp

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

func load(t *testing.T, name string, into any) {
	t.Helper()
	// The vectors live beside the ports, not inside this package, because all
	// ports must read the same bytes. A copy per language is how two ports
	// come to be checked against different contracts.
	b, err := os.ReadFile(filepath.Join("..", "vectors", name))
	if err != nil {
		t.Fatalf("cannot read vectors/%s: %v", name, err)
	}
	if err := json.Unmarshal(b, into); err != nil {
		t.Fatalf("cannot parse vectors/%s: %v", name, err)
	}
}

func TestIdentityHeaderVectors(t *testing.T) {
	var v struct {
		Cases []struct {
			Name      string  `json:"name"`
			Header    string  `json:"header"`
			OK        bool    `json:"ok"`
			AgentID   *string `json:"agentId"`
			ChainID   *string `json:"chainId"`
			Footprint *string `json:"footprint"`
			Reason    *string `json:"reason"`
		} `json:"cases"`
	}
	load(t, "identity_header.json", &v)
	if len(v.Cases) == 0 {
		t.Fatal("no cases")
	}
	for _, c := range v.Cases {
		got, reason := ParseAgentIdentity(c.Header)
		if (reason == "") != c.OK {
			t.Errorf("%s: ok=%v, want %v (reason %q)",
				c.Name, reason == "", c.OK, reason)
			continue
		}
		if !c.OK {
			if c.Reason != nil && reason != *c.Reason {
				t.Errorf("%s: reason=%q, want %q", c.Name, reason, *c.Reason)
			}
			continue
		}
		// Compared as decimal strings: the vectors carry uint256 ids, which a
		// JSON number cannot represent.
		if got.AgentID.String() != *c.AgentID {
			t.Errorf("%s: agentId=%s, want %s",
				c.Name, got.AgentID, *c.AgentID)
		}
		if got.ChainID.String() != *c.ChainID {
			t.Errorf("%s: chainId=%s, want %s",
				c.Name, got.ChainID, *c.ChainID)
		}
		if got.Footprint != *c.Footprint {
			t.Errorf("%s: footprint=%q, want %q",
				c.Name, got.Footprint, *c.Footprint)
		}
	}
}

// TestStripOWSIsNotTrimSpace states the property directly as well as through
// the vectors, so a failure says WHY rather than listing twenty-two cases.
func TestStripOWSIsNotTrimSpace(t *testing.T) {
	nonOWS := []string{"\n", "\r", "\v", "\f", "\u0085", " ", " ",
		" ", " ", "　"}
	for _, ch := range nonOWS {
		in := "x" + ch
		if StripOWS(in) != in {
			t.Errorf("StripOWS removed %q, which is not OWS. RFC 9110 5.5 is "+
				"SP and HTAB only; this is the TrimSpace bug the vectors "+
				"exist to catch.", ch)
		}
	}
	for _, ch := range []string{" ", "\t"} {
		if StripOWS(ch+"x"+ch) != "x" {
			t.Errorf("StripOWS failed to remove %q", ch)
		}
	}
}

func TestFormatterRefusesWhatParserRefuses(t *testing.T) {
	one := big.NewInt(1)
	neg := big.NewInt(-1)
	for _, c := range []struct {
		name            string
		agent, chain    *big.Int
		footprint       string
	}{
		{"negative agent", neg, one, "0xab"},
		{"negative chain", one, neg, "0xab"},
		{"separator in footprint", one, one, "0x;ab"},
		{"leading space", one, one, " 0xab"},
		{"trailing NBSP", one, one, "0xab "},
	} {
		if _, err := FormatAgentIdentity(c.agent, c.chain, c.footprint); err == nil {
			t.Errorf("%s: formatter emitted a header the parser would refuse",
				c.name)
		}
	}
}

func TestScopeVectors(t *testing.T) {
	var v struct {
		Cases []struct {
			McpMethod string `json:"mcpMethod"`
			McpName   string `json:"mcpName"`
			Scope     string `json:"scope"`
		} `json:"cases"`
	}
	load(t, "scope.json", &v)
	for _, c := range v.Cases {
		if got := ScopeFor(c.McpMethod, c.McpName); got != c.Scope {
			t.Errorf("ScopeFor(%q,%q)=%q, want %q",
				c.McpMethod, c.McpName, got, c.Scope)
		}
	}
}

func TestTierVectors(t *testing.T) {
	var v struct {
		CanonicalTier []struct {
			Input     string  `json:"input"`
			OK        bool    `json:"ok"`
			Canonical *string `json:"canonical"`
		} `json:"canonicalTier"`
		NarrowTier []struct {
			Asserted  string  `json:"asserted"`
			Ceiling   string  `json:"ceiling"`
			OK        bool    `json:"ok"`
			Effective *string `json:"effective"`
		} `json:"narrowTier"`
		Widens []struct {
			Asserted  string `json:"asserted"`
			Effective string `json:"effective"`
			Widens    bool   `json:"widens"`
		} `json:"widens"`
	}
	load(t, "tier.json", &v)

	for _, c := range v.CanonicalTier {
		got, err := CanonicalTier(c.Input)
		if (err == nil) != c.OK {
			t.Errorf("CanonicalTier(%q): ok=%v, want %v", c.Input, err == nil, c.OK)
			continue
		}
		if c.OK && got != *c.Canonical {
			t.Errorf("CanonicalTier(%q)=%q, want %q", c.Input, got, *c.Canonical)
		}
	}
	for _, c := range v.NarrowTier {
		got, err := NarrowTier(c.Asserted, c.Ceiling)
		if (err == nil) != c.OK {
			t.Errorf("NarrowTier(%q,%q): ok=%v, want %v",
				c.Asserted, c.Ceiling, err == nil, c.OK)
			continue
		}
		if c.OK && got != *c.Effective {
			t.Errorf("NarrowTier(%q,%q)=%q, want %q",
				c.Asserted, c.Ceiling, got, *c.Effective)
		}
	}
	for _, c := range v.Widens {
		if got := Widens(c.Asserted, c.Effective); got != c.Widens {
			t.Errorf("Widens(%q,%q)=%v, want %v",
				c.Asserted, c.Effective, got, c.Widens)
		}
	}
}
