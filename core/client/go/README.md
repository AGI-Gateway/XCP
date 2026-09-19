# XCP Go Client

Idiomatic Go client using the standard library plus `golang.org/x/crypto/sha3`
for the keccak footprint.

```bash
go get github.com/AGI-Gateway/XCP/client/go
```

```go
import xcp "github.com/AGI-Gateway/XCP/client/go"

id := xcp.Identity{AgentID: 42001, ChainID: 8453,
    CertPath: "agent.crt", KeyPath: "agent.key", CAPath: "ca.crt"}
c, err := xcp.NewClient("https://gateway.example.com", id)
c.Connect()
defer c.Close()

m := &xcp.Mandate{MandateID: "m1", Delegator: "0xSPONSOR",
    Scope: []string{"mcp:tools/echo"}, NotAfter: time.Now().Add(time.Hour).Unix()}
out, err := c.CallTool("research", "echo", map[string]any{"text": "hi"}, m)
```

`CallTool` / `Delegate` / `ChainTools` map to A2T / A2A / T2T. Errors carry the
gateway's 401/403 reason.
