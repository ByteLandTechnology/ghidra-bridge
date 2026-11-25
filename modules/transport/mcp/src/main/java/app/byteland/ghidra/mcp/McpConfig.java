package app.byteland.ghidra.mcp;

import app.byteland.ghidra.agent.AgentConfig;
import app.byteland.ghidra.network.NetworkBinding;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.LinkedHashSet;
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
    String host,
    int port,
    String path,
    String token,
    String sessionId,
    String toolPrefix,
    Set<String> allowedOrigins) {
  public static final int DEFAULT_PORT = 8766;
  public static final String DEFAULT_TOOL_PREFIX = "ghidra";
  public static final String ALLOWED_ORIGINS_ENV = "GHIDRA_MCP_ALLOWED_ORIGINS";
  private static final String NONE_ORIGINS = "none";
  private static final Pattern TOOL_PREFIX = Pattern.compile("[A-Za-z][A-Za-z0-9_-]{0,63}");
  private static final String DEFAULT_LOOPBACK_HOST =
      InetAddress.getLoopbackAddress().getHostAddress();
  private static final Set<String> ALLOWED =
      Set.of(
          "host",
          "port",
          "path",
          "session_id",
          "token",
          "tool_prefix",
          "allowed_origins",
          "jar");

  public McpConfig(
      String host, int port, String path, String token, String sessionId, String toolPrefix) {
    this(host, port, path, token, sessionId, toolPrefix, null);
  }

  public McpConfig {
    host = textOrDefault(host, DEFAULT_LOOPBACK_HOST);
    AgentConfig.requireValidPort(port);
    path = AgentConfig.normalizePath(path, "/mcp");
    token = AgentConfig.optionalText(token);
    NetworkBinding.requireTokenForNonLoopback(host, token);
    sessionId = textOrDefault(sessionId, "ghidra-bridge");
    toolPrefix = requireToolPrefix(textOrDefault(toolPrefix, DEFAULT_TOOL_PREFIX));
    allowedOrigins = normalizeAllowedOrigins(allowedOrigins, token);
  }

  public static McpConfig fromMap(Map<String, String> args) {
    return fromMap(args, System.getenv());
  }

  static McpConfig fromMap(Map<String, String> args, Map<String, String> env) {
    Objects.requireNonNull(args, "args");
    Objects.requireNonNull(env, "env");
    AgentConfig.rejectUnknown(args, ALLOWED);
    return new McpConfig(
        args.get("host"),
        portOrDefault(args.get("port")),
        args.get("path"),
        args.get("token"),
        args.get("session_id"),
        args.get("tool_prefix"),
        parseAllowedOrigins(resolveRawAllowedOrigins(args, env)));
  }

  public String endpoint() {
    return "http://" + host + ":" + port + path;
  }

  static String tryNormalizeOrigin(String rawOrigin) {
    try {
      return parseOrigin(rawOrigin).normalized();
    } catch (IllegalArgumentException invalid) {
      return null;
    }
  }

  private static String resolveRawAllowedOrigins(Map<String, String> args, Map<String, String> env) {
    String fromArgs = AgentConfig.optionalText(args.get("allowed_origins"));
    if (fromArgs != null) {
      return fromArgs;
    }
    if (args.containsKey("allowed_origins")) {
      return null;
    }
    return AgentConfig.optionalText(env.get(ALLOWED_ORIGINS_ENV));
  }

  private static Set<String> parseAllowedOrigins(String value) {
    String normalizedValue = AgentConfig.optionalText(value);
    if (normalizedValue == null) {
      return null;
    }
    if (NONE_ORIGINS.equalsIgnoreCase(normalizedValue)) {
      return Set.of();
    }
    Set<String> origins = new LinkedHashSet<>();
    for (String part : normalizedValue.split(",", -1)) {
      String candidate = part.trim();
      if (candidate.isEmpty()) {
        throw new IllegalArgumentException("allowed_origins must not contain empty entries");
      }
      if (NONE_ORIGINS.equalsIgnoreCase(candidate)) {
        throw new IllegalArgumentException(
            "allowed_origins cannot combine 'none' with other origins");
      }
      origins.add(parseOrigin(candidate).normalized());
    }
    return Collections.unmodifiableSet(origins);
  }

  private static Set<String> normalizeAllowedOrigins(Set<String> origins, String token) {
    if (origins == null) {
      return null;
    }
    if (origins.isEmpty()) {
      return Set.of();
    }
    Set<String> normalized = new LinkedHashSet<>();
    for (String origin : origins) {
      if (origin == null) {
        throw new IllegalArgumentException("allowed_origins must not contain null");
      }
      ParsedOrigin parsed = parseOrigin(origin);
      NetworkBinding.requireTokenForNonLoopbackOrigin(parsed.host(), token);
      normalized.add(parsed.normalized());
    }
    return Collections.unmodifiableSet(normalized);
  }

  private static ParsedOrigin parseOrigin(String rawOrigin) {
    if (rawOrigin == null) {
      throw new IllegalArgumentException("origin is required");
    }
    String trimmed = rawOrigin.trim();
    if (trimmed.isEmpty()) {
      throw new IllegalArgumentException("origin must not be blank");
    }
    if (trimmed.contains("*")) {
      throw new IllegalArgumentException("wildcard origins are not allowed: " + trimmed);
    }
    if ("null".equalsIgnoreCase(trimmed)) {
      throw new IllegalArgumentException("null origin is not allowed");
    }
    URI uri;
    try {
      uri = new URI(trimmed);
    } catch (URISyntaxException error) {
      throw new IllegalArgumentException("invalid origin: " + trimmed, error);
    }
    String rawScheme = uri.getScheme();
    if (rawScheme == null) {
      throw new IllegalArgumentException("origin must specify http or https scheme: " + trimmed);
    }
    String scheme = rawScheme.toLowerCase(Locale.ROOT);
    if (!"http".equals(scheme) && !"https".equals(scheme)) {
      throw new IllegalArgumentException("origin scheme must be http or https: " + trimmed);
    }
    if (uri.isOpaque()) {
      throw new IllegalArgumentException("origin must use scheme://host[:port]: " + trimmed);
    }
    if (uri.getRawUserInfo() != null) {
      throw new IllegalArgumentException("origin must not include userinfo: " + trimmed);
    }
    if (uri.getRawPath() != null && !uri.getRawPath().isEmpty()) {
      throw new IllegalArgumentException("origin must not include a path: " + trimmed);
    }
    if (uri.getRawQuery() != null) {
      throw new IllegalArgumentException("origin must not include a query: " + trimmed);
    }
    if (uri.getRawFragment() != null) {
      throw new IllegalArgumentException("origin must not include a fragment: " + trimmed);
    }
    String rawHost = uri.getHost();
    String rawAuthority = uri.getRawAuthority();
    if (rawHost == null || rawHost.isBlank() || rawAuthority == null) {
      throw new IllegalArgumentException("origin must include a valid host: " + trimmed);
    }
    int port = uri.getPort();
    String expectedAuthority = port == -1 ? rawHost : rawHost + ":" + port;
    if (!rawAuthority.equals(expectedAuthority)) {
      throw new IllegalArgumentException("origin must use canonical host[:port]: " + trimmed);
    }
    if (port != -1) {
      AgentConfig.requireValidPort(port);
    }
    String host = rawHost.toLowerCase(Locale.ROOT);
    boolean defaultPort =
        port == -1
            || ("http".equals(scheme) && port == 80)
            || ("https".equals(scheme) && port == 443);
    String normalized = defaultPort ? scheme + "://" + host : scheme + "://" + host + ":" + port;
    return new ParsedOrigin(normalized, host);
  }

  private record ParsedOrigin(String normalized, String host) {}

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
