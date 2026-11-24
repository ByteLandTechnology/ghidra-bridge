package app.byteland.ghidra.network;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Checks network addresses and parses startup arguments for bridge transports.
 */
public final class NetworkBinding {
  public static final String DEFAULT_LOOPBACK_HOST =
      InetAddress.getLoopbackAddress().getHostAddress();
  public static final String DEFAULT_SESSION_ID = "ghidra-bridge";

  @FunctionalInterface
  interface HostResolver {
    InetAddress[] resolve(String host) throws UnknownHostException;
  }

  private NetworkBinding() {}

  public static void requireTokenForNonLoopback(String host, String token) {
    requireTokenForNonLoopback(host, token, InetAddress::getAllByName);
  }

  static void requireTokenForNonLoopback(String host, String token, HostResolver resolver) {
    if (isLoopback(host, resolver)) return;
    if (optionalText(token) == null) {
      throw new IllegalArgumentException("token is required when binding outside loopback");
    }
  }

  public static boolean bearerTokenMatches(String authorizationHeader, String expectedToken) {
    if (authorizationHeader == null || expectedToken == null) {
      return false;
    }
    return MessageDigest.isEqual(
        authorizationHeader.getBytes(StandardCharsets.UTF_8),
        ("Bearer " + expectedToken).getBytes(StandardCharsets.UTF_8));
  }

  public static boolean isLoopback(String host) {
    return isLoopback(host, InetAddress::getAllByName);
  }

  static boolean isLoopback(String host, HostResolver resolver) {
    Objects.requireNonNull(resolver, "resolver");
    String normalized = requiredText(host, "host");
    try {
      InetAddress[] addresses = resolver.resolve(normalized);
      if (addresses.length == 0) {
        return false;
      }
      for (InetAddress address : addresses) {
        if (!address.isLoopbackAddress()) return false;
      }
      return true;
    } catch (UnknownHostException error) {
      throw new IllegalArgumentException("host cannot be resolved: " + host, error);
    }
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

  public static void rejectUnknown(Map<String, String> args, Set<String> allowed) {
    Objects.requireNonNull(args, "args");
    Objects.requireNonNull(allowed, "allowed");
    for (String key : args.keySet()) {
      if (!allowed.contains(key)) {
        throw new IllegalArgumentException("unknown startup argument: " + key);
      }
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

  public static String optionalText(String value) {
    if (value == null) return null;
    String normalized = value.trim();
    return normalized.isEmpty() ? null : normalized;
  }

  public static String requiredText(String value, String field) {
    String normalized = optionalText(value);
    if (normalized == null) {
      throw new IllegalArgumentException(field + " is required");
    }
    return normalized;
  }

  public static String textOrDefault(String value, String fallback) {
    String normalized = optionalText(value);
    return normalized == null ? fallback : normalized;
  }

  public static String defaultSessionId(String candidate) {
    return textOrDefault(candidate, DEFAULT_SESSION_ID);
  }

  public static String normalizePath(String value, String fallback) {
    String normalized = textOrDefault(value, requiredText(fallback, "fallback"));
    return normalized.startsWith("/") ? normalized : "/" + normalized;
  }
}
