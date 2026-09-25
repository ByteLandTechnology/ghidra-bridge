package app.byteland.ghidra.mcp;

import app.byteland.ghidra.agent.AgentConfig;
import app.byteland.ghidra.network.NetworkBinding;
import java.net.InetAddress;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Configuration parameters for the MCP Streamable HTTP server.
 *
 * <p>{@code toolPrefix} is the first part of every tool name, such as {@code ghidra} in
 * {@code ghidra.program}. Give each server a different prefix to connect one client to several
 * servers without tool name conflicts.
 */
public record McpConfig(
    String host, int port, String path, String token, String sessionId, String toolPrefix) {
  public static final int DEFAULT_PORT = 8766;
  public static final String DEFAULT_TOOL_PREFIX = "ghidra";
  private static final Pattern TOOL_PREFIX = Pattern.compile("[A-Za-z][A-Za-z0-9_-]{0,63}");
  private static final String DEFAULT_LOOPBACK_HOST =
      InetAddress.getLoopbackAddress().getHostAddress();
  private static final Set<String> ALLOWED =
      Set.of("host", "port", "path", "session_id", "token", "tool_prefix", "jar");

  public McpConfig {
    host = textOrDefault(host, DEFAULT_LOOPBACK_HOST);
    AgentConfig.requireValidPort(port);
    path = AgentConfig.normalizePath(path, "/mcp");
    token = AgentConfig.optionalText(token);
    NetworkBinding.requireTokenForNonLoopback(host, token);
    sessionId = textOrDefault(sessionId, "ghidra-bridge");
    toolPrefix = requireToolPrefix(textOrDefault(toolPrefix, DEFAULT_TOOL_PREFIX));
  }

  public static McpConfig fromMap(Map<String, String> args) {
    Objects.requireNonNull(args, "args");
    AgentConfig.rejectUnknown(args, ALLOWED);
    return new McpConfig(
        args.get("host"),
        portOrDefault(args.get("port")),
        args.get("path"),
        args.get("token"),
        args.get("session_id"),
        args.get("tool_prefix"));
  }

  public String endpoint() {
    return "http://" + host + ":" + port + path;
  }

  private static int portOrDefault(String value) {
    Integer parsed = AgentConfig.optionalInteger(value, "port");
    return parsed == null ? DEFAULT_PORT : parsed;
  }

  /**
   * Checks a tool prefix. It starts with a letter and has 1 to 64 letters, digits, underscores,
   * or hyphens. A dot is not allowed because it separates the prefix from the domain.
   */
  public static String requireToolPrefix(String prefix) {
    if (prefix == null || !TOOL_PREFIX.matcher(prefix).matches()) {
      throw new IllegalArgumentException(
          "tool_prefix must start with a letter and contain 1..64 letters, digits, '_', or '-'");
    }
    return prefix;
  }

  private static String textOrDefault(String value, String fallback) {
    String normalized = AgentConfig.optionalText(value);
    return normalized == null ? fallback : normalized;
  }
}
