package app.byteland.ghidra.agent;

import app.byteland.ghidra.network.NetworkBinding;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Configuration values for a WebSocket bridge session.
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

  public static AgentConfig fromArgs(String... args) {
    return fromMap(NetworkBinding.parseArgs(args));
  }

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
}
