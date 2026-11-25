package app.byteland.ghidra.agent;

import app.byteland.ghidra.network.NetworkBinding;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

final class WebSocketHandshakeValidator {
  private static final String BAD_REQUEST_REASON = "Bad Request";
  private static final String FORBIDDEN_REASON = "Forbidden";
  private static final String REQUIRED_VERSION = "13";
  private static final int MIN_VALID_PORT = 1;
  private static final int MAX_VALID_PORT = 65_535;

  private WebSocketHandshakeValidator() {}

  static void validate(AgentConfig config, WebSocketHandshake.HandshakeRequest request) {
    requireServerConfig(config);
    NetworkBinding.HostValidationResult hostValidation =
        NetworkBinding.validateHostHeader(request.hostHeaders(), config.host(), config.port());
    validateWithHostResult(config, null, request, hostValidation);
  }

  static void validate(
      AgentConfig config, boolean loopbackListener, WebSocketHandshake.HandshakeRequest request) {
    requireServerConfig(config);
    NetworkBinding.HostValidationResult hostValidation =
        NetworkBinding.validateHostHeader(
            request.hostHeaders(), config.host(), config.port(), loopbackListener);
    validateWithHostResult(config, loopbackListener, request, hostValidation);
  }

  private static void requireServerConfig(AgentConfig config) {
    Objects.requireNonNull(config, "config");
    if (!config.isServerMode()) {
      throw new IllegalArgumentException("server-mode AgentConfig is required");
    }
  }

  private static void validateWithHostResult(
      AgentConfig config,
      Boolean loopbackListener,
      WebSocketHandshake.HandshakeRequest request,
      NetworkBinding.HostValidationResult hostValidation) {
    if (!hostValidation.isValid()) {
      int status = hostValidation.httpStatus();
      String reason = status == 403 ? FORBIDDEN_REASON : BAD_REQUEST_REASON;
      throw new WebSocketHandshake.HttpHandshakeException(
          status, reason, hostValidation.message());
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
    validateOrigin(config, loopbackListener, request);
    if (request.query().containsKey("token")) {
      throw new WebSocketHandshake.HttpHandshakeException(
          400, BAD_REQUEST_REASON, "Query-string tokens are not supported");
    }
    if (!NetworkBinding.bearerTokenMatches(
        request.headers().get("authorization"), config.token())) {
      throw new WebSocketHandshake.HttpHandshakeException(401, "Unauthorized", "Invalid token");
    }
  }

  private static void validateOrigin(
      AgentConfig config, Boolean loopbackListener, WebSocketHandshake.HandshakeRequest request) {
    List<String> origins = request.originHeaders();
    if (origins.isEmpty()) {
      return;
    }
    if (origins.size() > 1) {
      throw forbidden("Multiple Origin headers are not allowed");
    }
    String rawOrigin = origins.getFirst();
    if (rawOrigin == null || rawOrigin.isBlank()) {
      throw forbidden("Blank Origin header is not allowed");
    }
    String trimmedOrigin = rawOrigin.trim();
    if ("null".equalsIgnoreCase(trimmedOrigin)) {
      throw forbidden("Null Origin header is not allowed");
    }
    URI uri = parseOriginUri(trimmedOrigin);
    String originHost = uri.getHost();
    if (!isAllowedOriginHost(config.host(), loopbackListener, originHost)) {
      throw forbidden("Disallowed Origin header");
    }
  }

  private static URI parseOriginUri(String origin) {
    final URI uri;
    try {
      uri = new URI(origin);
    } catch (URISyntaxException invalidOrigin) {
      throw forbidden("Malformed Origin header");
    }
    String scheme = uri.getScheme();
    if (scheme == null
        || (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme))
        || uri.isOpaque()) {
      throw forbidden("Origin must use http or https scheme");
    }
    if (uri.getRawUserInfo() != null || uri.getUserInfo() != null) {
      throw forbidden("Origin must not include userinfo");
    }
    String rawPath = uri.getRawPath();
    if (rawPath != null && !rawPath.isEmpty()) {
      throw forbidden("Origin must not include path");
    }
    if (uri.getRawQuery() != null || uri.getRawFragment() != null) {
      throw forbidden("Origin must not include query or fragment");
    }
    String host = uri.getHost();
    if (host == null || host.isBlank()) {
      throw forbidden("Origin must include host");
    }
    String rawAuthority = uri.getRawAuthority();
    if (rawAuthority != null && rawAuthority.endsWith(":")) {
      throw forbidden("Origin has empty port");
    }
    int port = uri.getPort();
    if (port != -1 && (port < MIN_VALID_PORT || port > MAX_VALID_PORT)) {
      throw forbidden("Origin port out of range");
    }
    return uri;
  }

  private static boolean isAllowedOriginHost(
      String configHost, Boolean loopbackListener, String originHost) {
    if (configHost == null || configHost.isBlank()) {
      return false;
    }
    InetAddress originLiteral = NetworkBinding.parseIpLiteral(originHost);
    if (originLiteral != null && originLiteral.isAnyLocalAddress()) {
      return false;
    }
    if (NetworkBinding.hostsMatch(configHost, originHost)) {
      return true;
    }
    boolean listenerIsLoopback =
        loopbackListener != null ? loopbackListener : isLoopbackListener(configHost);
    return NetworkBinding.isLiteralLoopbackHost(originHost) && listenerIsLoopback;
  }

  private static boolean isLoopbackListener(String configHost) {
    if (NetworkBinding.isLiteralLoopbackHost(configHost)) {
      return true;
    }
    if (NetworkBinding.parseIpLiteral(configHost) != null) {
      return false;
    }
    try {
      return NetworkBinding.isLoopback(configHost.trim());
    } catch (IllegalArgumentException unresolvedConfigHost) {
      return false;
    }
  }

  private static WebSocketHandshake.HttpHandshakeException forbidden(String message) {
    return new WebSocketHandshake.HttpHandshakeException(403, FORBIDDEN_REASON, message);
  }
}
