# XCP Clients

Four clients, one interface. Each opens a channel-bound session to an XCP
gateway and drives the three interaction types (A2T tool calls, A2A delegation,
T2T chaining) with a mandate proof on every governed action.

| Client | Path | mTLS | Best for |
|--------|------|------|----------|
| Python | [`python/`](python/) | full | the reference; scripting, services |
| Go | [`go/`](go/) | full | production services, high throughput |
| Java | [`java/`](java/) | via JVM keystore | JVM shops; dependency-free |
| Browser | [`browser/`](browser/) | delegated | web agents (delegated-session model) |

All four target the same gateway HTTP/JSON API, so you can mix them. The Python
client also signs EIP-712 mandates (sponsor side); the others attach a mandate
proof they're given.

## Python

```python
import sys; sys.path.insert(0, "python")
from xcp_client import XCPClient, AgentIdentity, sign_mandate
import time

identity = AgentIdentity(agent_id=42001, private_key="0x…",
                         cert_path="agent.crt", key_path="agent.key",
                         ca_path="ca.crt")
client = XCPClient("https://gateway.example.com", identity)
client.connect()

mandate = sign_mandate(identity.private_key, "m1", identity.address,
                       ["mcp:tools/research.*"], int(time.time()) + 3600)
result = client.call_tool("research", "fetch", {"url": "…"}, mandate=mandate)
client.close()
```

## Go

```go
id := xcp.Identity{AgentID: 42001, ChainID: 8453,
    CertPath: "agent.crt", KeyPath: "agent.key", CAPath: "ca.crt"}
c, _ := xcp.NewClient("https://gateway.example.com", id)
c.Connect()
m := &xcp.Mandate{MandateID: "m1", Scope: []string{"mcp:tools/echo"},
    NotAfter: time.Now().Add(time.Hour).Unix()}
out, _ := c.CallTool("research", "echo", map[string]any{"text": "hi"}, m)
```

## Java

```java
var id = new XCPClient.Identity(42001, 8453);
try (var c = new XCPClient("https://gateway.example.com", id)) {
    c.connect();
    var m = new XCPClient.Mandate("m1", "0xSPONSOR",
        List.of("mcp:tools/echo"), Instant.now().plusSeconds(3600).getEpochSecond());
    System.out.println(c.callTool("research", "echo", "{\"text\":\"hi\"}", m));
}
```

## Browser

Open [`browser/index.html`](browser/index.html) against a running gateway. Since
JS can't present an mTLS client cert, the browser uses a delegated-session model:
a trusted local service holds the certificate and the page drives it. The demo
derives a development footprint the gateway's local registry accepts.
