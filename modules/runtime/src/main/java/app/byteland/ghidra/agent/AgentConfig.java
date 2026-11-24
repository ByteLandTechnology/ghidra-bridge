package app.byteland.ghidra.agent;

import app.byteland.ghidra.network.NetworkBinding;
import java.io.ByteArrayOutputStream;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/** Configuration values for a bridge runtime session. */
public record AgentConfig(
    String wsUrl,
    String host,
    Integer port,
    String path,
    String token,
    String sessionId,
    Integer exitDeadlineSeconds) {
  private static final String DEFAULT_LOOPBACK_HOST =
      InetAddress.getLoopbackAddress().getHostAddress();
  private static final Set<String> ALLOWED =
      Set.of("ws_url", "host", "port", "path", "session_id", "token", "jar", "exit_deadline_sec");

  public AgentConfig {
    boolean pathWasProvided = optionalText(path) != null;
    wsUrl = optionalText(wsUrl);
    host = optionalText(host);
    path = normalizePath(path, "/ws/agent");
    token = optionalText(token);
    sessionId = required(sessionId, "session_id");
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
    if (port != null) requireValidPort(port);
    if (port != null && host == null) host = DEFAULT_LOOPBACK_HOST;
    if (port != null) NetworkBinding.requireTokenForNonLoopback(host, token);
    if (exitDeadlineSeconds != null && wsUrl == null) {
      throw new IllegalArgumentException("exit_deadline_sec requires ws_url");
    }
    if (exitDeadlineSeconds != null && exitDeadlineSeconds < 1) {
      throw new IllegalArgumentException("exit_deadline_sec must be positive");
    }
  }

  public static AgentConfig fromArgs(String... args) {
    return fromMap(parseArgs(args));
  }

  public static AgentConfig fromMap(Map<String, String> args) {
    Objects.requireNonNull(args, "args");
    rejectUnknown(args, ALLOWED);
    return new AgentConfig(
        args.get("ws_url"),
        args.get("host"),
        optionalInteger(args.get("port"), "port"),
        args.get("path"),
        args.get("token"),
        args.get("session_id"),
        optionalInteger(args.get("exit_deadline_sec"), "exit_deadline_sec"));
  }

  public static Map<String, String> parseArgs(String... args) {
    Map<String, String> parsed = new LinkedHashMap<>();
    if (args == null) return parsed;
    for (String raw : args) {
      if (raw == null || raw.isBlank()) continue;
      String argument = raw.trim();
      int separator = argument.indexOf('=');
      if (separator <= 0) {
        throw new IllegalArgumentException("expected key=value argument but got: " + argument);
      }
      String key = argument.substring(0, separator);
      if (parsed.putIfAbsent(key, argument.substring(separator + 1)) != null) {
        throw new IllegalArgumentException("duplicate startup argument: " + key);
      }
    }
    return parsed;
  }

  public boolean isOutboundMode() {
    return wsUrl != null;
  }

  public boolean isServerMode() {
    return port != null;
  }

  public String redactedWsUrl() {
    return redactWsUrl(wsUrl);
  }

  public static String redactWsUrl(String wsUrl) {
    String normalized = optionalText(wsUrl);
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

  @SuppressWarnings("PMD.PreserveStackTrace")
  public static URI parseWsUri(String wsUrl) {
    String normalized = optionalText(wsUrl);
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
      requireValidPort(uri.getPort());
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

  @SuppressWarnings("PMD.PreserveStackTrace")
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

  public static void rejectUnknown(Map<String, String> args, Set<String> allowed) {
    for (String key : args.keySet()) {
      if (!allowed.contains(key))
        throw new IllegalArgumentException("unknown startup argument: " + key);
    }
  }

  public static void requireValidPort(int port) {
    if (port < 1 || port > 65535) {
      throw new IllegalArgumentException("port must be in 1..65535");
    }
  }

  public static Integer optionalInteger(String value, String field) {
    String normalized = optionalText(value);
    if (normalized == null) return null;
    try {
      return Integer.valueOf(normalized);
    } catch (NumberFormatException error) {
      throw new IllegalArgumentException(field + " must be an integer", error);
    }
  }

  private static String required(String value, String field) {
    String normalized = optionalText(value);
    if (normalized == null) throw new IllegalArgumentException(field + " is required");
    return normalized;
  }

  public static String optionalText(String value) {
    if (value == null) return null;
    String normalized = value.trim();
    return normalized.isEmpty() ? null : normalized;
  }

  public static String normalizePath(String value, String fallback) {
    String normalized = optionalText(value);
    if (normalized == null) normalized = fallback;
    return normalized.startsWith("/") ? normalized : "/" + normalized;
  }
}
