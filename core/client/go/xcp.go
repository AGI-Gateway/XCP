// Package xcp is a Go client for XCP (Multi-Model Secure Context Protocol).
//
// It implements the XCP session flow against an XCP gateway: open a
// channel-bound mTLS session, then call tools (A2T), delegate to peers (A2A),
// or chain tools (T2T) with a mandate proof attached to every governed action.
//
// This mirrors the Python client in ../python and talks to the same reference
// gateway in ../../gateway over HTTP/JSON.
//
// Status: XCP / ERC-8004x are draft proposals. Pin to a released spec before
// production use.
package xcp

import (
	"bytes"
	"golang.org/x/crypto/sha3"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Rail bits select which payment rails a session may use.
const (
	RailX402 = 1 << 0
	RailAP2  = 1 << 1
	RailMPP  = 1 << 2
	RailACP  = 1 << 3
)

// Identity holds the agent's ERC-8004 identity and mTLS material.
type Identity struct {
	AgentID  uint64
	ChainID  uint64
	CertPath string // PEM client cert
	KeyPath  string // PEM private key
	CAPath   string // CA bundle to verify the gateway
}

// Mandate is a signed, scoped, time-bounded authorization from a sponsor.
type Mandate struct {
	MandateID string   `json:"mandateId"`
	Delegator string   `json:"delegator"`
	Scope     []string `json:"mandateScope"`
	NotAfter  int64    `json:"notAfter"`
	Leaf      string   `json:"leaf"`
	Proof     []string `json:"proof"`
	Signature string   `json:"signature"`
}

func (m *Mandate) header() string {
	b, _ := json.Marshal(m)
	return string(b)
}

// Session is a live XCP session bound to a certificate footprint.
type Session struct {
	AgentID     uint64
	ChainID     uint64
	Footprint   string
	SessionID   string
	MandateRoot string
	Rails       int
}

// Client opens a channel-bound session to a gateway and drives A2T/A2A/T2T.
type Client struct {
	GatewayURL string
	Identity   Identity
	Session    *Session
	http       *http.Client
}

// CertFootprint computes keccak256(DER(cert)) — the on-chain session key.
func CertFootprint(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("no PEM block in certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	h := sha3.NewLegacyKeccak256()
	h.Write(cert.Raw)
	return "0x" + hex.EncodeToString(h.Sum(nil)), nil
}

// NewClient builds a client, loading mTLS material if provided.
func NewClient(gatewayURL string, id Identity) (*Client, error) {
	tr := &http.Transport{}
	if id.CertPath != "" && id.KeyPath != "" {
		cert, err := tls.LoadX509KeyPair(id.CertPath, id.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("load client cert: %w", err)
		}
		cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
		if id.CAPath != "" {
			ca, err := os.ReadFile(id.CAPath)
			if err != nil {
				return nil, err
			}
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM(ca)
			cfg.RootCAs = pool
		}
		tr.TLSClientConfig = cfg
	}
	return &Client{
		GatewayURL: strings.TrimRight(gatewayURL, "/"),
		Identity:   id,
		http:       &http.Client{Transport: tr, Timeout: 15 * time.Second},
	}, nil
}

func (c *Client) localFootprint() string {
	if c.Identity.CertPath != "" {
		if pemBytes, err := os.ReadFile(c.Identity.CertPath); err == nil {
			if fp, err := CertFootprint(pemBytes); err == nil {
				return fp
			}
		}
	}
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte(fmt.Sprintf("agent:%d", c.Identity.AgentID)))
	return "0x" + hex.EncodeToString(h.Sum(nil))
}

// Connect opens a channel-bound session with the gateway.
func (c *Client) Connect() (*Session, error) {
	fp := c.localFootprint()
	body := map[string]any{
		"agentId": c.Identity.AgentID, "chainId": c.Identity.ChainID,
		"footprint": fp,
	}
	var out struct {
		SessionID   string `json:"sessionId"`
		MandateRoot string `json:"mandateRoot"`
		Rails       int    `json:"rails"`
	}
	if err := c.post("/v1/session/open", body, nil, &out); err != nil {
		return nil, err
	}
	c.Session = &Session{
		AgentID: c.Identity.AgentID, ChainID: c.Identity.ChainID, Footprint: fp,
		SessionID: out.SessionID, MandateRoot: out.MandateRoot, Rails: out.Rails,
	}
	return c.Session, nil
}

// Close ends the session.
func (c *Client) Close() {
	if c.Session != nil {
		_ = c.post("/v1/session/close", map[string]any{}, nil, nil)
		c.Session = nil
	}
}

// CallTool invokes an MCP tool through the gateway (scope mcp:tools/<tool>).
func (c *Client) CallTool(server, tool string, args map[string]any, m *Mandate) (map[string]any, error) {
	var out map[string]any
	err := c.post("/v1/a2t/call",
		map[string]any{"server": server, "tool": tool, "arguments": args}, m, &out)
	return out, err
}

// Delegate hands a task to a peer agent (scope a2a:delegate/<peer>).
func (c *Client) Delegate(peerDID string, task map[string]any, m *Mandate) (map[string]any, error) {
	var out map[string]any
	err := c.post("/v1/a2a/delegate",
		map[string]any{"peerDid": peerDID, "task": task}, m, &out)
	return out, err
}

// ChainTools pipes one tool's output into another (scope t2t:chain/<src>-><dst>).
func (c *Client) ChainTools(src, dst string, payload map[string]any, m *Mandate) (map[string]any, error) {
	var out map[string]any
	err := c.post("/v1/t2t/pipe",
		map[string]any{"src": src, "dst": dst, "payload": payload}, m, &out)
	return out, err
}

func (c *Client) post(path string, body any, m *Mandate, out any) error {
	buf, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", c.GatewayURL+path, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Session != nil {
		req.Header.Set("XCP-Agent-Identity",
			fmt.Sprintf("%d;%d;%s", c.Session.AgentID, c.Session.ChainID, c.Session.Footprint))
	}
	if m != nil {
		req.Header.Set("XCP-Mandate", m.header())
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == 401 {
		return fmt.Errorf("session rejected: %s", string(data))
	}
	if resp.StatusCode == 403 {
		return fmt.Errorf("mandate denied: %s", string(data))
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("gateway error %d: %s", resp.StatusCode, string(data))
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}
