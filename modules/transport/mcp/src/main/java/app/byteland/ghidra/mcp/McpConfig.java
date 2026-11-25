package app.byteland.ghidra.mcp;

import app.byteland.ghidra.agent.AgentConfig;
import app.byteland.ghidra.network.NetworkBinding;
import java.net.InetAddress;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Configuration parameters for the MCP Streamable HTTP server.
 *
 * <p>{@code toolPrefix} is the first part of every tool name. An example is {@code ghidra} in
 * {@code ghidra.program}. Give each server a different prefix. Then one client can connect to
 * several servers without tool name conflicts.
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
   * Checks a tool prefix. It starts with a letter. It has 1 to 64 letters, digits, underscores,
   * or hyphens. A dot is not permitted because it separates the prefix from the domain.
   */
  public static String requireToolPrefix(String prefix) {
    if (prefix == null || !TOOL_PREFIX.matcher(prefix).matches()) {
      throw new IllegalArgumentException(
          "tool_prefix must start with a letter and contain 1..64 letters, digits, '_', or '-'");
    }
    return prefix;
  }

  /**
   * Derives a valid MCP tool prefix from a program name for a fallback port session.
   */
  public static String deriveFallbackToolPrefix(String programName, int port) {
    AgentConfig.requireValidPort(port);
    String fallback = DEFAULT_TOOL_PREFIX + "_" + port;
    String sanitized = sanitizeProgramIdentifier(programName);
    if (sanitized.isEmpty() || DEFAULT_TOOL_PREFIX.equalsIgnoreCase(sanitized)) {
      return requireToolPrefix(fallback);
    }
    if (!isAsciiLetter(sanitized.charAt(0))) {
      sanitized = DEFAULT_TOOL_PREFIX + "_" + sanitized;
    }
    if (sanitized.length() > 64) {
      sanitized = trimEdgeSeparators(sanitized.substring(0, 64));
    }
    if (sanitized.isEmpty()
        || !isAsciiLetter(sanitized.charAt(0))
        || DEFAULT_TOOL_PREFIX.equalsIgnoreCase(sanitized)) {
      return requireToolPrefix(fallback);
    }
    return requireToolPrefix(sanitized);
  }

  /**
   * Derives a sanitized session identifier from a program name and bound fallback port.
   */
  public static String deriveFallbackSessionId(String programName, int port) {
    AgentConfig.requireValidPort(port);
    String suffix = "-" + port;
    String sanitized = sanitizeProgramIdentifier(programName);
    if (sanitized.isEmpty()) {
      sanitized = DEFAULT_TOOL_PREFIX;
    }
    int maxBaseLength = 64 - suffix.length();
    if (sanitized.length() > maxBaseLength) {
      sanitized = trimEdgeSeparators(sanitized.substring(0, maxBaseLength));
      if (sanitized.isEmpty()) {
        sanitized = DEFAULT_TOOL_PREFIX;
      }
    }
    return sanitized + suffix;
  }

  public static String sanitizeProgramIdentifier(String rawName) {
    if (rawName == null) {
      return "";
    }
    String lower = rawName.trim().toLowerCase(Locale.ROOT);
    StringBuilder builder = new StringBuilder(lower.length());
    boolean lastUnderscore = false;
    for (int i = 0; i < lower.length(); i++) {
      char ch = lower.charAt(i);
      if (isAsciiLetter(ch) || (ch >= '0' && ch <= '9') || ch == '-') {
        builder.append(ch);
        lastUnderscore = false;
      } else if (!lastUnderscore && builder.length() > 0) {
        builder.append('_');
        lastUnderscore = true;
      }
    }
    return trimEdgeSeparators(builder.toString());
  }

  private static String trimEdgeSeparators(String value) {
    int start = 0;
    int end = value.length();
    while (start < end && (value.charAt(start) == '_' || value.charAt(start) == '-')) {
      start++;
    }
    while (end > start && (value.charAt(end - 1) == '_' || value.charAt(end - 1) == '-')) {
      end--;
    }
    return value.substring(start, end);
  }

  private static boolean isAsciiLetter(char ch) {
    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z');
  }

  private static String textOrDefault(String value, String fallback) {
    String normalized = AgentConfig.optionalText(value);
    return normalized == null ? fallback : normalized;
  }
}
