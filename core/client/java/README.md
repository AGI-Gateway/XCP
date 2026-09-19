# XCP Java Client

Dependency-free client using `java.net.http`. Compiles on JDK 11+.

```bash
javac XCPClient.java
java org.xcp.XCPClient http://localhost:8080   # runs the demo main()
```

The footprint uses `SHA3-256` from the JDK as a stand-in; swap in a real
keccak256 (e.g. BouncyCastle) to match on-chain values exactly. JSON handling is
a tiny built-in serializer for the known request/response shapes — replace with
a real JSON library for production.
