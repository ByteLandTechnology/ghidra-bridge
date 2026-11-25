package app.byteland.ghidra.network;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Locale;
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
  private static final int IPV4_BYTE_LENGTH = 4;
  private static final int IPV6_BYTE_LENGTH = 16;

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

  public static void requireTokenForNonLoopbackOrigin(String host, String token) {
    requireTokenForNonLoopbackOrigin(host, token, InetAddress::getAllByName);
  }

  static void requireTokenForNonLoopbackOrigin(
      String host, String token, HostResolver resolver) {
    Objects.requireNonNull(resolver, "resolver");
    if (optionalText(token) != null) {
      return;
    }
    boolean loopback;
    try {
      loopback = isLoopback(host, resolver);
    } catch (IllegalArgumentException unresolved) {
      loopback = false;
    }
    if (!loopback) {
      throw new IllegalArgumentException(
          "token is required when allowed_origins includes a non-loopback origin");
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
    InetAddress literal = parseIpLiteral(normalized);
    if (literal != null) {
      return literal.isLoopbackAddress();
    }
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

  /**
   * Normalizes a host string by trimming ASCII whitespace, stripping surrounding IPv6 brackets when
   * a colon is present, and lowercasing in {@link Locale#ROOT}.
   */
  public static String normalizeHost(String host) {
    Objects.requireNonNull(host, "host");
    String trimmed = host.trim();
    if (trimmed.length() > 2
        && trimmed.charAt(0) == '['
        && trimmed.charAt(trimmed.length() - 1) == ']'
        && trimmed.indexOf(':') >= 0) {
      trimmed = trimmed.substring(1, trimmed.length() - 1);
    }
    return trimmed.toLowerCase(Locale.ROOT);
  }

  /**
   * Returns {@code true} when {@code host} is {@code localhost} (case-insensitive) or parses
   * syntactically as a literal IPv4/IPv6 loopback address ({@code 127.0.0.0/8}, {@code ::1}, or
   * IPv4-mapped loopback {@code ::ffff:127.0.0.0/104}) without performing DNS lookups.
   */
  public static boolean isLiteralLoopbackHost(String host) {
    if (host == null) {
      return false;
    }
    String normalized = normalizeHost(host);
    if ("localhost".equals(normalized)) {
      return true;
    }
    InetAddress literal = parseIpLiteral(normalized);
    return literal != null && literal.isLoopbackAddress();
  }

  /**
   * Compares two host strings case-insensitively and across canonical IPv4/IPv6 literal
   * representations without performing DNS lookups.
   */
  public static boolean hostsMatch(String firstHost, String secondHost) {
    if (firstHost == null || secondHost == null) {
      return false;
    }
    String normalizedFirst = normalizeHost(firstHost);
    String normalizedSecond = normalizeHost(secondHost);
    if (normalizedFirst.isEmpty() || normalizedSecond.isEmpty()) {
      return false;
    }
    if (normalizedFirst.equals(normalizedSecond)) {
      return true;
    }
    InetAddress firstLiteral = parseIpLiteral(normalizedFirst);
    if (firstLiteral == null) {
      return false;
    }
    InetAddress secondLiteral = parseIpLiteral(normalizedSecond);
    return firstLiteral.equals(secondLiteral);
  }

  /**
   * Parses a strict IPv4 or (optionally bracketed) IPv6 literal into an {@link InetAddress} without
   * performing DNS resolution, or returns {@code null} if {@code host} is not a valid IP literal.
   */
  public static InetAddress parseIpLiteral(String host) {
    if (host == null) {
      return null;
    }
    String normalized = normalizeHost(host);
    if (normalized.isEmpty()) {
      return null;
    }
    byte[] bytes =
        normalized.indexOf(':') >= 0 ? parseIpv6Literal(normalized) : parseIpv4Literal(normalized);
    if (bytes == null) {
      return null;
    }
    try {
      return InetAddress.getByAddress(bytes);
    } catch (UnknownHostException impossible) {
      return null;
    }
  }

  /**
   * Parses a strict dotted-quad decimal IPv4 literal (rejecting leading zeros, short forms, and
   * non-ASCII digits) into a 4-byte array, or returns {@code null} if invalid.
   */
  public static byte[] parseIpv4Literal(String literal) {
    if (literal == null || literal.isEmpty() || literal.length() > 15) {
      return null;
    }
    byte[] bytes = new byte[IPV4_BYTE_LENGTH];
    int octetIndex = 0;
    int value = 0;
    int digits = 0;
    for (int i = 0; i < literal.length(); i++) {
      char ch = literal.charAt(i);
      if (ch == '.') {
        if (digits == 0 || octetIndex == 3) {
          return null;
        }
        bytes[octetIndex++] = (byte) value;
        value = 0;
        digits = 0;
      } else if (ch >= '0' && ch <= '9') {
        if (digits == 1 && value == 0) {
          return null;
        }
        value = value * 10 + (ch - '0');
        digits++;
        if (digits > 3 || value > 255) {
          return null;
        }
      } else {
        return null;
      }
    }
    if (digits == 0 || octetIndex != 3) {
      return null;
    }
    bytes[3] = (byte) value;
    return bytes;
  }

  /**
   * Parses a strict unbracketed IPv6 literal (supporting {@code ::} zero-compression and trailing
   * dotted-quad IPv4, while rejecting {@code %} zone IDs) into a 16-byte array, or returns {@code
   * null} if invalid.
   */
  public static byte[] parseIpv6Literal(String literal) {
    if (literal == null || literal.length() < 2 || literal.indexOf('%') >= 0) {
      return null;
    }
    int doubleColon = literal.indexOf("::");
    if (doubleColon >= 0 && literal.indexOf("::", doubleColon + 1) >= 0) {
      return null;
    }
    String headPart = doubleColon >= 0 ? literal.substring(0, doubleColon) : literal;
    String tailPart = doubleColon >= 0 ? literal.substring(doubleColon + 2) : null;

    byte[] headBytes =
        headPart.isEmpty() ? new byte[0] : parseIpv6Groups(headPart, tailPart == null);
    if (headBytes == null || (doubleColon < 0 && headPart.isEmpty())) {
      return null;
    }
    if (tailPart == null) {
      return headBytes.length == IPV6_BYTE_LENGTH ? headBytes : null;
    }
    byte[] tailBytes = tailPart.isEmpty() ? new byte[0] : parseIpv6Groups(tailPart, true);
    if (tailBytes == null || headBytes.length + tailBytes.length >= IPV6_BYTE_LENGTH) {
      return null;
    }
    byte[] result = new byte[IPV6_BYTE_LENGTH];
    System.arraycopy(headBytes, 0, result, 0, headBytes.length);
    System.arraycopy(tailBytes, 0, result, IPV6_BYTE_LENGTH - tailBytes.length, tailBytes.length);
    return result;
  }

  private static byte[] parseIpv6Groups(String part, boolean allowTrailingIpv4) {
    if (part.charAt(0) == ':' || part.charAt(part.length() - 1) == ':') {
      return null;
    }
    String[] groups = part.split(":", -1);
    byte[] buffer = new byte[IPV6_BYTE_LENGTH];
    int offset = 0;
    for (int i = 0; i < groups.length; i++) {
      String group = groups[i];
      if (group.isEmpty()) {
        return null;
      }
      if (group.indexOf('.') >= 0) {
        if (!allowTrailingIpv4 || i != groups.length - 1 || offset > 12) {
          return null;
        }
        byte[] ipv4 = parseIpv4Literal(group);
        if (ipv4 == null) {
          return null;
        }
        System.arraycopy(ipv4, 0, buffer, offset, IPV4_BYTE_LENGTH);
        offset += IPV4_BYTE_LENGTH;
      } else {
        if (group.length() > 4 || offset > 14) {
          return null;
        }
        int word = 0;
        for (int j = 0; j < group.length(); j++) {
          int digit = asciiHexDigit(group.charAt(j));
          if (digit < 0) {
            return null;
          }
          word = (word << 4) | digit;
        }
        buffer[offset++] = (byte) (word >>> 8);
        buffer[offset++] = (byte) word;
      }
    }
    return Arrays.copyOf(buffer, offset);
  }

  private static int asciiHexDigit(char ch) {
    if (ch >= '0' && ch <= '9') {
      return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
      return ch - 'a' + 10;
    }
    if (ch >= 'A' && ch <= 'F') {
      return ch - 'A' + 10;
    }
    return -1;
  }
}
