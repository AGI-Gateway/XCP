package org.xcp;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.List;
import java.util.Map;

/**
 * Java client for XCP (Multi-Model Secure Context Protocol).
 *
 * <p>Opens a channel-bound session to an XCP gateway and drives the three
 * interaction types (A2T tool calls, A2A delegation, T2T chaining) with a
 * mandate proof attached to every governed action. Mirrors the Python and Go
 * clients and talks to the same reference gateway over HTTP/JSON.
 *
 * <p>This class keeps JSON handling dependency-free with a tiny serializer for
 * the small, well-known request/response shapes. For production, swap in a
 * real JSON library and a keccak256 implementation (e.g. BouncyCastle) for the
 * certificate footprint.
 *
 * <p>Status: XCP / ERC-8004x are draft proposals.
 */
public final class XCPClient implements AutoCloseable {

    /** railsBitmap bits. */
    public static final int RAIL_X402 = 1, RAIL_AP2 = 2, RAIL_MPP = 4, RAIL_ACP = 8;

    public static final class Identity {
        public long agentId;
        public long chainId = 8453;
        public String certPath;   // PEM client cert (optional)
        public Identity(long agentId, long chainId) {
            this.agentId = agentId; this.chainId = chainId;
        }
    }

    /** A signed, scoped, time-bounded authorization from a sponsor. */
    public static final class Mandate {
        public String mandateId, delegator, leaf = "", signature = "";
        public List<String> scope;
        public long notAfter;
        public List<String> proof = List.of();

        public Mandate(String id, String delegator, List<String> scope, long notAfter) {
            this.mandateId = id; this.delegator = delegator;
            this.scope = scope; this.notAfter = notAfter;
        }

        String header() {
            return "{\"mandateId\":\"" + mandateId + "\",\"delegator\":\"" + delegator
                 + "\",\"mandateScope\":" + Json.arr(scope)
                 + ",\"notAfter\":" + notAfter
                 + ",\"leaf\":\"" + leaf + "\",\"proof\":" + Json.arr(proof)
                 + ",\"signature\":\"" + signature + "\"}";
        }
    }

    public static final class Session {
        public long agentId, chainId;
        public String footprint, sessionId = "", mandateRoot = "";
        public int rails;
    }

    public static final class XCPException extends RuntimeException {
        public XCPException(String m) { super(m); }
    }

    private final String gatewayUrl;
    private final Identity identity;
    private final HttpClient http;
    private Session session;

    public XCPClient(String gatewayUrl, Identity identity) {
        this.gatewayUrl = gatewayUrl.replaceAll("/+$", "");
        this.identity = identity;
        this.http = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build();
    }

    /** keccak256(DER(cert)) footprint. Uses SHA3-256 as a stand-in; swap for
     *  a real keccak256 (BouncyCastle) to match on-chain values exactly. */
    public static String certFootprint(byte[] certPem) throws Exception {
        String body = new String(certPem)
            .replaceAll("-----BEGIN CERTIFICATE-----", "")
            .replaceAll("-----END CERTIFICATE-----", "")
            .replaceAll("\\s", "");
        byte[] der = java.util.Base64.getDecoder().decode(body);
        MessageDigest md = MessageDigest.getInstance("SHA3-256");
        return "0x" + toHex(md.digest(der));
    }

    private String localFootprint() {
        try {
            if (identity.certPath != null) {
                return certFootprint(Files.readAllBytes(Path.of(identity.certPath)));
            }
        } catch (Exception ignored) { }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA3-256");
            return "0x" + toHex(md.digest(("agent:" + identity.agentId).getBytes()));
        } catch (Exception e) { throw new XCPException("footprint: " + e.getMessage()); }
    }

    /** Open a channel-bound session with the gateway. */
    public Session connect() {
        String fp = localFootprint();
        String body = "{\"agentId\":" + identity.agentId + ",\"chainId\":"
                    + identity.chainId + ",\"footprint\":\"" + fp + "\"}";
        String resp = post("/v1/session/open", body, null);
        Session s = new Session();
        s.agentId = identity.agentId; s.chainId = identity.chainId; s.footprint = fp;
        s.sessionId = Json.str(resp, "sessionId");
        s.mandateRoot = Json.str(resp, "mandateRoot");
        s.rails = (int) Json.num(resp, "rails");
        this.session = s;
        return s;
    }

    /** A2T: call an MCP tool (scope mcp:tools/&lt;tool&gt;). */
    public String callTool(String server, String tool, String argsJson, Mandate m) {
        String body = "{\"server\":\"" + server + "\",\"tool\":\"" + tool
                    + "\",\"arguments\":" + (argsJson == null ? "{}" : argsJson) + "}";
        return post("/v1/a2t/call", body, m);
    }

    /** A2A: delegate a task to a peer (scope a2a:delegate/&lt;peer&gt;). */
    public String delegate(String peerDid, String taskJson, Mandate m) {
        String body = "{\"peerDid\":\"" + peerDid + "\",\"task\":"
                    + (taskJson == null ? "{}" : taskJson) + "}";
        return post("/v1/a2a/delegate", body, m);
    }

    /** T2T: chain one tool into another (scope t2t:chain/&lt;src&gt;-&gt;&lt;dst&gt;). */
    public String chainTools(String src, String dst, String payloadJson, Mandate m) {
        String body = "{\"src\":\"" + src + "\",\"dst\":\"" + dst
                    + "\",\"payload\":" + (payloadJson == null ? "{}" : payloadJson) + "}";
        return post("/v1/t2t/pipe", body, m);
    }

    @Override public void close() {
        if (session != null) {
            try { post("/v1/session/close", "{}", null); } catch (Exception ignored) { }
            session = null;
        }
    }

    private String post(String path, String body, Mandate m) {
        HttpRequest.Builder b = HttpRequest.newBuilder()
            .uri(URI.create(gatewayUrl + path))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body));
        if (session != null) {
            b.header("XCP-Agent-Identity",
                session.agentId + ";" + session.chainId + ";" + session.footprint);
        }
        if (m != null) b.header("XCP-Mandate", m.header());
        try {
            HttpResponse<String> r = http.send(b.build(), HttpResponse.BodyHandlers.ofString());
            if (r.statusCode() == 401) throw new XCPException("session rejected: " + r.body());
            if (r.statusCode() == 403) throw new XCPException("mandate denied: " + r.body());
            if (r.statusCode() != 200) throw new XCPException("gateway " + r.statusCode() + ": " + r.body());
            return r.body();
        } catch (IOException | InterruptedException e) {
            throw new XCPException("request failed: " + e.getMessage());
        }
    }

    private static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    /** Minimal JSON helpers for the small, known shapes used here. */
    static final class Json {
        static String arr(List<String> xs) {
            StringBuilder sb = new StringBuilder("[");
            for (int i = 0; i < xs.size(); i++) {
                if (i > 0) sb.append(",");
                sb.append("\"").append(xs.get(i)).append("\"");
            }
            return sb.append("]").toString();
        }
        static String str(String json, String key) {
            String needle = "\"" + key + "\":\"";
            int i = json.indexOf(needle);
            if (i < 0) return "";
            i += needle.length();
            int j = json.indexOf("\"", i);
            return j < 0 ? "" : json.substring(i, j);
        }
        static double num(String json, String key) {
            String needle = "\"" + key + "\":";
            int i = json.indexOf(needle);
            if (i < 0) return 0;
            i += needle.length();
            int j = i;
            while (j < json.length() && "-0123456789.".indexOf(json.charAt(j)) >= 0) j++;
            try { return Double.parseDouble(json.substring(i, j)); }
            catch (Exception e) { return 0; }
        }
    }

    /** Tiny demo entry point (requires a running gateway). */
    public static void main(String[] args) throws Exception {
        Identity id = new Identity(42001, 8453);
        try (XCPClient c = new XCPClient(
                args.length > 0 ? args[0] : "http://localhost:8080", id)) {
            Session s = c.connect();
            System.out.println("session: agent=" + s.agentId + " footprint=" + s.footprint);
            Mandate m = new Mandate("m1", "0xSPONSOR",
                List.of("mcp:tools/echo"), System.currentTimeMillis() / 1000 + 3600);
            System.out.println(c.callTool("research", "echo",
                "{\"text\":\"hello\"}", m));
        }
    }
}
