package app.byteland.ghidra.mcp;

import app.byteland.ghidra.agent.AgentConfig;
import app.byteland.ghidra.network.NetworkBinding;
import java.net.InetAddress;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Configuration parameters for the MCP Streamable HTTP server.
 */
public record McpConfig(String host, int port, String path, String token, String sessionId) {
  public static final int DEFAULT_PORT = 8766;
  private static final String DEFAULT_LOOPBACK_HOST =
      InetAddress.getLoopbackAddress().getHostAddress();
  private static final Set<String> ALLOWED =
      Set.of("host", "port", "path", "session_id", "token", "jar");

  public McpConfig {
    host = textOrDefault(host, DEFAULT_LOOPBACK_HOST);
    AgentConfig.requireValidPort(port);
    path = AgentConfig.normalizePath(path, "/mcp");
    token = AgentConfig.optionalText(token);
    NetworkBinding.requireTokenForNonLoopback(host, token);
    sessionId = textOrDefault(sessionId, "ghidra-bridge");
  }

  public static McpConfig fromMap(Map<String, String> args) {
    Objects.requireNonNull(args, "args");
    AgentConfig.rejectUnknown(args, ALLOWED);
    return new McpConfig(
        args.get("host"),
        portOrDefault(args.get("port")),
        args.get("path"),
        args.get("token"),
        args.get("session_id"));
  }

  public String endpoint() {
    return "http://" + host + ":" + port + path;
  }

  private static int portOrDefault(String value) {
    Integer parsed = AgentConfig.optionalInteger(value, "port");
    return parsed == null ? DEFAULT_PORT : parsed;
  }

  private static String textOrDefault(String value, String fallback) {
    String normalized = AgentConfig.optionalText(value);
    return normalized == null ? fallback : normalized;
  }
}
