import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.PosixFilePermission;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/** Pentest Master Burp Bridge v2. Read-only, metadata-only API. */
public class Extension implements BurpExtension {
    private static final int PORT = 17779;
    private static final int MAX_LIMIT = 100;
    private MontoyaApi api;
    private HttpServer server;
    private ExecutorService workers;
    private String secret;
    private final String instanceId = UUID.randomUUID().toString();
    private Path tokenFile;

    @Override
    public void initialize(MontoyaApi montoya) {
        this.api = montoya;
        api.extension().setName("Pentest Master Burp Bridge");
        try {
            byte[] random = new byte[32];
            new SecureRandom().nextBytes(random);
            secret = Base64.getUrlEncoder().withoutPadding().encodeToString(random);
            tokenFile = Path.of(System.getProperty("user.home"), ".config", "pentest-master", "burp-bridge.token");
            Files.createDirectories(tokenFile.getParent());
            Path temp = Files.createTempFile(tokenFile.getParent(), "bridge-", ".tmp",
                PosixFilePermissions.asFileAttribute(Set.of(
                    PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE)));
            Files.writeString(temp, secret + "\n", StandardCharsets.US_ASCII);
            Files.move(temp, tokenFile, StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING);

            server = HttpServer.create(new InetSocketAddress("127.0.0.1", PORT), 0);
            server.createContext("/health", this::health);
            server.createContext("/history", this::history);
            workers = Executors.newFixedThreadPool(2);
            server.setExecutor(workers);
            server.start();
            api.extension().registerUnloadingHandler(this::stop);
            api.logging().logToOutput("[Pentest Master] Burp Bridge v2 listening on 127.0.0.1:" + PORT);
        } catch (Exception ex) {
            stop();
            api.logging().logToError("[Pentest Master] Bridge startup failed: " + ex.getMessage());
            throw new IllegalStateException("Burp Bridge failed to start", ex);
        }
    }

    private void stop() {
        if (server != null) server.stop(0);
        if (workers != null) workers.shutdownNow();
        try {
            if (tokenFile != null && Files.exists(tokenFile)
                    && Files.readString(tokenFile).trim().equals(secret)) {
                Files.deleteIfExists(tokenFile);
            }
        } catch (IOException ignored) { }
    }

    private static boolean ipv4(String host) {
        if (host == null || !host.matches("[0-9]{1,3}(\\.[0-9]{1,3}){3}")) return false;
        String[] parts = host.split("\\.");
        for (String part : parts) if (Integer.parseInt(part) > 255) return false;
        return true;
    }

    private static String escape(String s) {
        StringBuilder out = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            if (c == '"' || c == '\\') out.append('\\').append(c);
            else if (c < 32) out.append(String.format("\\u%04x", (int)c));
            else out.append(c);
        }
        return out.append('"').toString();
    }

    private static String sha256(String value) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder text = new StringBuilder();
            for (byte b : hash) text.append(String.format("%02x", b & 0xff));
            return text.toString();
        } catch (Exception ex) { throw new IllegalStateException(ex); }
    }

    private boolean authenticated(HttpExchange x) throws IOException {
        // Host-only binding is not authentication: local processes also need a token.
        String supplied = x.getRequestHeaders().getFirst("X-Pentest-Master-Token");
        if (supplied == null || !MessageDigest.isEqual(
                supplied.getBytes(StandardCharsets.US_ASCII),
                secret.getBytes(StandardCharsets.US_ASCII))) {
            reply(x, 401, "{\"error\":\"unauthorized\"}");
            return false;
        }
        if (!"GET".equals(x.getRequestMethod())) {
            x.getResponseHeaders().set("Allow", "GET");
            reply(x, 405, "{\"error\":\"method_not_allowed\"}");
            return false;
        }
        return true;
    }

    private static void reply(HttpExchange x, int status, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        x.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        x.getResponseHeaders().set("Cache-Control", "no-store");
        x.sendResponseHeaders(status, bytes.length);
        try (var body = x.getResponseBody()) { body.write(bytes); }
        x.close();
    }

    private static Map<String, String> query(String raw) {
        Map<String, String> values = new HashMap<>();
        if (raw == null) return values;
        for (String piece : raw.split("&", 10)) {
            String[] kv = piece.split("=", 2);
            values.put(URLDecoder.decode(kv[0], StandardCharsets.UTF_8),
                    kv.length == 2 ? URLDecoder.decode(kv[1], StandardCharsets.UTF_8) : "");
        }
        return values;
    }

    private void health(HttpExchange x) throws IOException {
        if (!authenticated(x)) return;
        reply(x, 200, "{\"status\":\"running\",\"component\":\"burp_bridge\","
            + "\"mode\":\"metadata_read_only\",\"instance_id\":" + escape(instanceId) + "}");
    }

    private void history(HttpExchange x) throws IOException {
        if (!authenticated(x)) return;
        try {
            Map<String, String> params = query(x.getRequestURI().getRawQuery());
            String host = params.get("host");
            if (!ipv4(host)) {
                reply(x, 400, "{\"error\":\"ipv4_host_required\"}");
                return;
            }
            int after = Integer.parseInt(params.getOrDefault("after", "0"));
            int limit = Integer.parseInt(params.getOrDefault("limit", "50"));
            if (after < 0 || limit < 1 || limit > MAX_LIMIT) {
                reply(x, 400, "{\"error\":\"invalid_pagination\"}");
                return;
            }
            AtomicInteger accepted = new AtomicInteger();
            // Filtering happens inside Burp before any metadata leaves the extension.
            List<ProxyHttpRequestResponse> selected = api.proxy().history(item -> {
                if (accepted.get() >= limit) return false;
                try {
                    if (item.id() <= after || !host.equals(item.finalRequest().httpService().host())) return false;
                    accepted.incrementAndGet();
                    return true;
                } catch (RuntimeException ex) { return false; }
            });
            StringBuilder json = new StringBuilder("{\"status\":\"ok\",\"instance_id\":")
                .append(escape(instanceId)).append(",\"host\":").append(escape(host))
                .append(",\"entries\":[");
            int count = 0;
            for (ProxyHttpRequestResponse item : selected) {
                try {
                    var request = item.finalRequest();
                    var service = request.httpService();
                    int port = service.port();
                    if (port < 1 || port > 65535) continue;
                    boolean hasResponse = item.hasResponse();
                    int status = hasResponse ? item.originalResponse().statusCode() : 0;
                    if (count++ > 0) json.append(',');
                    json.append("{\"id\":").append(item.id())
                        .append(",\"host\":").append(escape(host))
                        .append(",\"port\":").append(port)
                        .append(",\"tls\":").append(service.secure())
                        .append(",\"method\":").append(escape(request.method()))
                        .append(",\"path_sha256\":").append(escape(sha256(request.pathWithoutQuery())))
                        .append(",\"has_response\":").append(hasResponse)
                        .append(",\"status_code\":").append(status)
                        .append(",\"observed_at\":").append(escape(item.time().toString()))
                        .append('}');
                } catch (RuntimeException ex) { /* skip malformed item */ }
            }
            json.append("],\"count\":").append(count).append('}');
            reply(x, 200, json.toString());
        } catch (IllegalArgumentException ex) {
            reply(x, 400, "{\"error\":\"invalid_parameters\"}");
        } catch (Exception ex) {
            api.logging().logToError("[Pentest Master] History read failed: " + ex.getClass().getSimpleName());
            reply(x, 500, "{\"error\":\"history_unavailable\"}");
        }
    }
}
