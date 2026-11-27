package app.byteland.ghidra.agent;

import app.byteland.ghidra.network.NetworkBinding;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Configuration values for a WebSocket bridge session.
 *
 * @param wsUrl outbound WebSocket URL, or {@code null} in server mode
 * @param host server listen host, or {@code null} in outbound mode
 * @param port server listen TCP port, or {@code null} in outbound mode
 * @param path WebSocket endpoint path
 * @param token optional bearer authentication token
 * @param sessionId unique session identifier
 * @param exitDeadlineSeconds optional shutdown deadline in seconds for outbound mode
 */
public record AgentConfig(
    String wsUrl,
    String host,
    Integer port,
    String path,
    String token,
    String sessionId,
    Integer exitDeadlineSeconds) {
  private static final Set<String> ALLOWED =
      Set.of("ws_url", "host", "port", "path", "session_id", "token", "jar", "exit_deadline_sec");

  /** Validates and normalizes runtime configuration fields. */
  public AgentConfig {
    boolean pathWasProvided = NetworkBinding.optionalText(path) != null;
    wsUrl = NetworkBinding.optionalText(wsUrl);
    host = NetworkBinding.optionalText(host);
    path = NetworkBinding.normalizePath(path, AgentWebSocketServer.DEFAULT_PATH);
    token = NetworkBinding.optionalText(token);
    sessionId = NetworkBinding.requiredText(sessionId, "session_id");
    if (wsUrl == null && port == null) {
      throw new IllegalArgumentException("either ws_url or port is required");
    }
    if (wsUrl != null && (port != null || host != null || pathWasProvided)) {
      throw new IllegalArgumentException("ws_url conflicts with host/port/path");
    }
    if (wsUrl != null) {
      URI uri = parseWsUri(wsUrl);
      NetworkBinding.requireTokenForNonLoopback(uri.getHost(), token);
    }
    if (port != null) NetworkBinding.requireValidPort(port);
    if (port != null && host == null) host = NetworkBinding.DEFAULT_LOOPBACK_HOST;
    if (port != null) NetworkBinding.requireTokenForNonLoopback(host, token);
    if (exitDeadlineSeconds != null && wsUrl == null) {
      throw new IllegalArgumentException("exit_deadline_sec requires ws_url");
    }
    if (exitDeadlineSeconds != null && exitDeadlineSeconds < 1) {
      throw new IllegalArgumentException("exit_deadline_sec must be positive");
    }
  }

  /**
   * Parses configuration from {@code key=value} startup arguments.
   *
   * @param args raw {@code key=value} argument strings
   * @return validated runtime configuration
   */
  public static AgentConfig fromArgs(String... args) {
    return fromMap(NetworkBinding.parseArgs(args));
  }

  /**
   * Builds configuration from a key-value startup argument map.
   *
   * @param args startup argument map
   * @return validated runtime configuration
   */
  public static AgentConfig fromMap(Map<String, String> args) {
    Objects.requireNonNull(args, "args");
    NetworkBinding.rejectUnknown(args, ALLOWED);
    return new AgentConfig(
        args.get("ws_url"),
        args.get("host"),
        NetworkBinding.optionalInteger(args.get("port"), "port"),
        args.get("path"),
        args.get("token"),
        args.get("session_id"),
        NetworkBinding.optionalInteger(args.get("exit_deadline_sec"), "exit_deadline_sec"));
  }

  /**
   * Reports whether this configuration connects outbound to a remote WebSocket URL.
   *
   * @return {@code true} if {@code wsUrl} is configured
   */
  public boolean isOutboundMode() {
    return wsUrl != null;
  }

  /**
   * Reports whether this configuration listens on a local TCP port.
   *
   * @return {@code true} if {@code port} is configured
   */
  public boolean isServerMode() {
    return port != null;
  }

  /**
   * Returns the local WebSocket listener URL in server mode.
   *
   * @return WebSocket endpoint URL, or {@code null} in outbound mode
   */
  public String serverEndpoint() {
    if (port == null) {
      return null;
    }
    String formattedHost =
        host.indexOf(':') >= 0 && !host.startsWith("[") ? "[" + host + "]" : host;
    return "ws://" + formattedHost + ":" + port + path;
  }

  /**
   * Returns the outbound WebSocket URL with query and fragment components redacted.
   *
   * @return redacted WebSocket URL, or {@code null} if unset
   */
  public String redactedWsUrl() {
    return redactWsUrl(wsUrl);
  }

  /**
   * Redacts userinfo, query, and fragment components from a WebSocket URL string.
   *
   * @param wsUrl candidate WebSocket URL, or {@code null}
   * @return redacted WebSocket URL, or {@code null} when blank
   */
  public static String redactWsUrl(String wsUrl) {
    String normalized = NetworkBinding.optionalText(wsUrl);
    if (normalized == null) return null;
    int query = normalized.indexOf('?');
    int fragment = normalized.indexOf('#');
    int separator;
    if (query < 0) separator = fragment;
    else if (fragment < 0) separator = query;
    else separator = Math.min(query, fragment);
    String base = separator < 0 ? normalized : normalized.substring(0, separator);
    String stripped = stripAuthorityUserInfo(base);
    return separator < 0 ? stripped : stripped + "?<redacted>";
  }

  /**
   * Parses and validates an outbound {@code ws} or {@code wss} URI without credentials.
   *
   * @param wsUrl outbound WebSocket URL string
   * @return validated WebSocket URI
   */
  public static URI parseWsUri(String wsUrl) {
    String normalized = NetworkBinding.optionalText(wsUrl);
    if (normalized == null) {
      throw new IllegalArgumentException("ws_url is invalid");
    }
    URI uri;
    try {
      uri = new URI(normalized);
    } catch (URISyntaxException invalidUrl) {
      throw new IllegalArgumentException("ws_url is invalid");
    }
    String scheme = uri.getScheme();
    if (scheme == null
        || uri.isOpaque()
        || (!"ws".equalsIgnoreCase(scheme) && !"wss".equalsIgnoreCase(scheme))) {
      throw new IllegalArgumentException("ws_url must use ws or wss scheme");
    }
    if (uri.getRawUserInfo() != null
        || (uri.getRawAuthority() != null && uri.getRawAuthority().indexOf('@') >= 0)) {
      throw new IllegalArgumentException("ws_url must not contain userinfo");
    }
    String uriHost = uri.getHost();
    if (uriHost == null || uriHost.isBlank()) {
      throw new IllegalArgumentException("ws_url must include a host");
    }
    if (uri.getPort() != -1) {
      NetworkBinding.requireValidPort(uri.getPort());
    }
    rejectQueryToken(uri.getRawQuery());
    return uri;
  }

  private static String stripAuthorityUserInfo(String base) {
    int schemeEnd = base.indexOf("://");
    int authorityStart;
    if (schemeEnd >= 0) {
      authorityStart = schemeEnd + 3;
    } else if (base.startsWith("//")) {
      authorityStart = 2;
    } else {
      authorityStart = 0;
    }
    int authorityEnd = base.length();
    for (int i = authorityStart; i < base.length(); i++) {
      char ch = base.charAt(i);
      if (ch == '/' || ch == '\\') {
        authorityEnd = i;
        break;
      }
    }
    if (authorityEnd <= authorityStart) {
      return base;
    }
    int atIndex = base.lastIndexOf('@', authorityEnd - 1);
    if (atIndex < authorityStart) {
      return base;
    }
    return base.substring(0, authorityStart) + base.substring(atIndex + 1);
  }

  private static void rejectQueryToken(String rawQuery) {
    if (rawQuery == null || rawQuery.isEmpty()) {
      return;
    }
    int start = 0;
    while (start <= rawQuery.length()) {
      int amp = rawQuery.indexOf('&', start);
      String part = amp < 0 ? rawQuery.substring(start) : rawQuery.substring(start, amp);
      if (!part.isEmpty()) {
        int eq = part.indexOf('=');
        String rawKey = eq >= 0 ? part.substring(0, eq) : part;
        String rawValue = eq >= 0 ? part.substring(eq + 1) : "";
        String key = decodeQueryComponent(rawKey);
        decodeQueryComponent(rawValue);
        if ("token".equalsIgnoreCase(key)) {
          throw new IllegalArgumentException("Query-string tokens are not supported");
        }
      }
      if (amp < 0) {
        break;
      }
      start = amp + 1;
    }
  }

  private static String decodeQueryComponent(String value) {
    StringBuilder decoded = new StringBuilder(value.length());
    ByteArrayOutputStream percentBytes = null;
    int i = 0;
    while (i < value.length()) {
      char ch = value.charAt(i);
      if (ch == '%') {
        if (i + 2 >= value.length()) {
          throw new IllegalArgumentException("ws_url query contains malformed percent-encoding");
        }
        int hi = hexDigit(value.charAt(i + 1));
        int lo = hexDigit(value.charAt(i + 2));
        if (hi < 0 || lo < 0) {
          throw new IllegalArgumentException("ws_url query contains malformed percent-encoding");
        }
        if (percentBytes == null) {
          percentBytes = new ByteArrayOutputStream(4);
        }
        percentBytes.write((hi << 4) | lo);
        i += 3;
      } else {
        if (percentBytes != null && percentBytes.size() > 0) {
          appendUtf8Bytes(decoded, percentBytes.toByteArray());
          percentBytes.reset();
        }
        decoded.append(ch == '+' ? ' ' : ch);
        i++;
      }
    }
    if (percentBytes != null && percentBytes.size() > 0) {
      appendUtf8Bytes(decoded, percentBytes.toByteArray());
    }
    return decoded.toString();
  }

  private static void appendUtf8Bytes(StringBuilder target, byte[] bytes) {
    try {
      target.append(
          StandardCharsets.UTF_8
              .newDecoder()
              .onMalformedInput(CodingErrorAction.REPORT)
              .onUnmappableCharacter(CodingErrorAction.REPORT)
              .decode(ByteBuffer.wrap(bytes)));
    } catch (CharacterCodingException invalidUtf8) {
      throw new IllegalArgumentException("ws_url query contains malformed percent-encoding");
    }
  }

  private static int hexDigit(char ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
  }
}
