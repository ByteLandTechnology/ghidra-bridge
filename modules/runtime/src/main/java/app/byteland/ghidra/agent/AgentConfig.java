package app.byteland.ghidra.agent;

import app.byteland.ghidra.network.NetworkBinding;
import java.net.InetAddress;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Configuration settings for a bridge runtime session.
 */
public record AgentConfig(
    String wsUrl, String host, Integer port, String path, String token, String sessionId) {
  private static final String DEFAULT_LOOPBACK_HOST =
      InetAddress.getLoopbackAddress().getHostAddress();
  private static final Set<String> ALLOWED =
      Set.of("ws_url", "host", "port", "path", "session_id", "token", "jar");

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
        args.get("session_id"));
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
    if (wsUrl == null) return null;
    int query = wsUrl.indexOf('?');
    int fragment = wsUrl.indexOf('#');
    int separator;
    if (query < 0) separator = fragment;
    else if (fragment < 0) separator = query;
    else separator = Math.min(query, fragment);
    return separator < 0 ? wsUrl : wsUrl.substring(0, separator) + "?<redacted>";
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
