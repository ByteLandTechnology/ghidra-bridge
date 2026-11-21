package app.byteland.ghidra.agent;

import app.byteland.ghidra.network.NetworkBinding;
import java.net.InetAddress;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Configuration values for a bridge runtime session.
 *
 * @param wsUrl outbound WebSocket endpoint URL, or {@code null} in server mode
 * @param host listen host in server mode, or {@code null} in outbound mode
 * @param port listen port in server mode, or {@code null} in outbound mode
 * @param path WebSocket request path
 * @param token optional bearer authentication token
 * @param sessionId session identifier reported in envelopes and metadata
 * @param exitDeadlineSeconds optional JVM exit deadline in seconds for outbound mode
 */
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

  /** Validates and normalizes startup configuration values. */
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

  /**
   * Parses {@code key=value} startup arguments into an {@link AgentConfig}.
   *
   * @param args raw startup arguments
   * @return validated configuration
   */
  public static AgentConfig fromArgs(String... args) {
    return fromMap(parseArgs(args));
  }

  /**
   * Builds an {@link AgentConfig} from a parsed key-value argument map.
   *
   * @param args key-value startup arguments
   * @return validated configuration
   */
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

  /**
   * Parses {@code key=value} strings into an ordered map and rejects duplicate keys.
   *
   * @param args raw startup arguments
   * @return parsed key-value map
   */
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

  /**
   * Reports whether this configuration connects outbound to {@code ws_url}.
   *
   * @return {@code true} when {@code ws_url} is set
   */
  public boolean isOutboundMode() {
    return wsUrl != null;
  }

  /**
   * Reports whether this configuration listens on a local TCP {@code port}.
   *
   * @return {@code true} when {@code port} is set
   */
  public boolean isServerMode() {
    return port != null;
  }

  /**
   * Returns {@code wsUrl} with any query string or fragment replaced by {@code ?<redacted>}.
   *
   * @return redacted WebSocket URL, or {@code null} when {@code wsUrl} is {@code null}
   */
  public String redactedWsUrl() {
    if (wsUrl == null) return null;
    int query = wsUrl.indexOf('?');
    int fragment = wsUrl.indexOf('#');
    int separator;
    if (query < 0) separator = fragment;
    else if (fragment < 0) separator = query;
    else separator = Math.min(query, fragment);
    return separator < 0 ? wsUrl : wsUrl.substring(0, separator) + "?<redacted>";
  }

  /**
   * Throws {@link IllegalArgumentException} if {@code args} contains any key outside {@code allowed}.
   *
   * @param args parsed startup arguments
   * @param allowed permitted argument keys
   */
  public static void rejectUnknown(Map<String, String> args, Set<String> allowed) {
    for (String key : args.keySet()) {
      if (!allowed.contains(key))
        throw new IllegalArgumentException("unknown startup argument: " + key);
    }
  }

  /**
   * Validates that {@code port} is in the TCP range {@code 1..65535}.
   *
   * @param port TCP port number
   */
  public static void requireValidPort(int port) {
    if (port < 1 || port > 65535) {
      throw new IllegalArgumentException("port must be in 1..65535");
    }
  }

  /**
   * Parses an optional integer value for {@code field}.
   *
   * @param value raw text value, or {@code null}
   * @param field argument name used in error messages
   * @return parsed integer, or {@code null} when blank
   */
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

  /**
   * Trims {@code value} and converts blank text to {@code null}.
   *
   * @param value raw text value
   * @return trimmed non-empty text, or {@code null}
   */
  public static String optionalText(String value) {
    if (value == null) return null;
    String normalized = value.trim();
    return normalized.isEmpty() ? null : normalized;
  }

  /**
   * Normalizes an HTTP or WebSocket path so it starts with {@code /}.
   *
   * @param value raw path value, or {@code null}
   * @param fallback default path when {@code value} is blank
   * @return normalized path with a leading slash
   */
  public static String normalizePath(String value, String fallback) {
    String normalized = optionalText(value);
    if (normalized == null) normalized = fallback;
    return normalized.startsWith("/") ? normalized : "/" + normalized;
  }
}
