package app.byteland.ghidra.agent;

import app.byteland.ghidra.network.NetworkBinding;
import java.net.InetAddress;
import java.util.Locale;

final class WebSocketHandshakeValidator {
  private static final String BAD_REQUEST_REASON = "Bad Request";
  private static final String FORBIDDEN_REASON = "Forbidden";
  private static final String REQUIRED_VERSION = "13";

  private WebSocketHandshakeValidator() {}

  static void validate(AgentConfig config, WebSocketHandshake.HandshakeRequest request) {
    validate(config, config.port(), null, request);
  }

  static void validate(
      AgentConfig config,
      int boundPort,
      InetAddress localAddress,
      WebSocketHandshake.HandshakeRequest request) {
    if (!NetworkBinding.isAllowedHost(
        request.headerValues("host"), config.host(), boundPort, localAddress)) {
      throw new WebSocketHandshake.HttpHandshakeException(
          403, FORBIDDEN_REASON, "Forbidden Host header");
    }
    if (!NetworkBinding.isAllowedOrigin(request.headerValues("origin"), config.host())) {
      throw new WebSocketHandshake.HttpHandshakeException(
          403, FORBIDDEN_REASON, "Forbidden Origin header");
    }
    if (!"GET".equals(request.method())) {
      throw new WebSocketHandshake.HttpHandshakeException(
          405, "Method Not Allowed", "WebSocket upgrade requires GET");
    }
    if (!config.path().equals(request.path())) {
      throw new WebSocketHandshake.HttpHandshakeException(
          404, "Not Found", "Expected " + config.path());
    }
    String upgrade = request.headers().getOrDefault("upgrade", "");
    String connection = request.headers().getOrDefault("connection", "");
    String version = request.headers().get("sec-websocket-version");
    String key = request.headers().get("sec-websocket-key");
    if (!"websocket".equalsIgnoreCase(upgrade)) {
      throw new WebSocketHandshake.HttpHandshakeException(
          400, BAD_REQUEST_REASON, "Missing Upgrade: websocket");
    }
    if (!connection.toLowerCase(Locale.ROOT).contains("upgrade")) {
      throw new WebSocketHandshake.HttpHandshakeException(
          400, BAD_REQUEST_REASON, "Missing Connection: Upgrade");
    }
    if (!REQUIRED_VERSION.equals(version)) {
      throw new WebSocketHandshake.HttpHandshakeException(
          400, BAD_REQUEST_REASON, "Unsupported WebSocket version");
    }
    if (key == null || key.isBlank()) {
      throw new WebSocketHandshake.HttpHandshakeException(
          400, BAD_REQUEST_REASON, "Missing Sec-WebSocket-Key");
    }
    if (request.query().containsKey("token")) {
      throw new WebSocketHandshake.HttpHandshakeException(
          400, BAD_REQUEST_REASON, "Query-string tokens are not supported");
    }
    if (config.token() != null
        && !NetworkBinding.bearerTokenMatches(
            request.headers().get("authorization"), config.token())) {
      throw new WebSocketHandshake.HttpHandshakeException(401, "Unauthorized", "Invalid token");
    }
  }
}
