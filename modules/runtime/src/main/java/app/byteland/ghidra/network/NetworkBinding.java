package app.byteland.ghidra.network;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

public final class NetworkBinding {
  private NetworkBinding() {}

  public static void requireToken(String host, String token) {
    validateHost(host);
    if (token == null || token.isBlank()) {
      throw new IllegalArgumentException("token is required");
    }
  }

  public static boolean bearerTokenMatches(String authorizationHeader, String expectedToken) {
    if (authorizationHeader == null || expectedToken == null || expectedToken.isBlank()) {
      return false;
    }
    return MessageDigest.isEqual(
        authorizationHeader.getBytes(StandardCharsets.UTF_8),
        ("Bearer " + expectedToken).getBytes(StandardCharsets.UTF_8));
  }

  public static boolean isAllowedHostHeader(
      String hostHeader, String configuredHost, Integer configuredPort) {
    if (configuredHost == null || configuredHost.isBlank()) {
      return false;
    }
    return isAllowedHostHeader(
        hostHeader, configuredHost, configuredPort, isLoopback(configuredHost));
  }

  public static boolean isAllowedHostHeader(
      String hostHeader,
      String configuredHost,
      Integer configuredPort,
      boolean configuredLoopback) {
    if (hostHeader == null
        || hostHeader.isBlank()
        || configuredHost == null
        || configuredHost.isBlank()) {
      return false;
    }
    HostPort parsed = parseHostHeader(hostHeader);
    if (parsed == null) {
      return false;
    }
    String expectedHost = stripBrackets(configuredHost.trim());
    if (expectedHost.isEmpty()) {
      return false;
    }
    if (configuredLoopback) {
      if (parsed.port() != null
          && configuredPort != null
          && !parsed.port().equals(configuredPort)) {
        return false;
      }
      return "localhost".equalsIgnoreCase(parsed.host())
          || expectedHost.equalsIgnoreCase(parsed.host())
          || isLoopbackIpLiteral(parsed.host());
    }
    if (isWildcardHostLiteral(expectedHost)) {
      return true;
    }
    return expectedHost.equalsIgnoreCase(parsed.host())
        || sameIpLiteral(expectedHost, parsed.host());
  }

  public static boolean isLoopback(String host) {
    for (InetAddress address : resolveAddresses(host)) {
      if (!address.isLoopbackAddress()) return false;
    }
    return true;
  }

  private static void validateHost(String host) {
    resolveAddresses(host);
  }

  private static InetAddress[] resolveAddresses(String host) {
    if (host == null || host.isBlank()) {
      throw new IllegalArgumentException("host is required");
    }
    try {
      return InetAddress.getAllByName(host.trim());
    } catch (UnknownHostException error) {
      throw new IllegalArgumentException("host cannot be resolved: " + host, error);
    }
  }

  private static HostPort parseHostHeader(String raw) {
    if (raw.isEmpty()) {
      return null;
    }
    if (raw.charAt(0) == '[') {
      int close = raw.indexOf(']');
      if (close <= 1) {
        return null;
      }
      String ipv6 = raw.substring(1, close);
      if (parseIpv6Literal(ipv6) == null) {
        return null;
      }
      if (close == raw.length() - 1) {
        return new HostPort(ipv6, null);
      }
      if (raw.charAt(close + 1) != ':') {
        return null;
      }
      Integer port = parseStrictPort(raw.substring(close + 2));
      return port == null ? null : new HostPort(ipv6, port);
    }

    int colon = raw.indexOf(':');
    if (colon == 0) {
      return null;
    }
    if (colon > 0) {
      if (raw.indexOf(':', colon + 1) >= 0) {
        return null;
      }
      String hostPart = raw.substring(0, colon);
      Integer port = parseStrictPort(raw.substring(colon + 1));
      if (port == null || !isValidHostToken(hostPart)) {
        return null;
      }
      return new HostPort(hostPart, port);
    }
    return isValidHostToken(raw) ? new HostPort(raw, null) : null;
  }

  private static boolean isValidHostToken(String value) {
    if (value.isEmpty()) {
      return false;
    }
    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      if (c <= 0x20
          || c >= 0x7F
          || c == '/'
          || c == '\\'
          || c == '@'
          || c == '?'
          || c == '#'
          || c == '['
          || c == ']') {
        return false;
      }
    }
    return true;
  }

  private static Integer parseStrictPort(String portText) {
    if (portText.isEmpty() || portText.length() > 5) {
      return null;
    }
    int port = 0;
    for (int i = 0; i < portText.length(); i++) {
      char c = portText.charAt(i);
      if (c < '0' || c > '9') {
        return null;
      }
      port = port * 10 + (c - '0');
    }
    return port >= 1 && port <= 65535 ? port : null;
  }

  private static String stripBrackets(String host) {
    if (host.length() >= 2 && host.charAt(0) == '[' && host.charAt(host.length() - 1) == ']') {
      return host.substring(1, host.length() - 1);
    }
    return host;
  }

  private static boolean isLoopbackIpLiteral(String host) {
    byte[] ipv4 = parseIpv4Literal(host);
    if (ipv4 != null) {
      return ipv4[0] == 127;
    }
    InetAddress ipv6 = parseIpv6Literal(host);
    return ipv6 != null && ipv6.isLoopbackAddress();
  }

  private static boolean isWildcardHostLiteral(String host) {
    byte[] ipv4 = parseIpv4Literal(host);
    if (ipv4 != null) {
      return ipv4[0] == 0 && ipv4[1] == 0 && ipv4[2] == 0 && ipv4[3] == 0;
    }
    InetAddress ipv6 = parseIpv6Literal(host);
    return ipv6 != null && ipv6.isAnyLocalAddress();
  }

  private static boolean sameIpLiteral(String first, String second) {
    byte[] firstBytes = parseIpLiteralBytes(first);
    if (firstBytes == null) {
      return false;
    }
    byte[] secondBytes = parseIpLiteralBytes(second);
    return secondBytes != null && Arrays.equals(firstBytes, secondBytes);
  }

  private static byte[] parseIpLiteralBytes(String host) {
    byte[] ipv4 = parseIpv4Literal(host);
    if (ipv4 != null) {
      return ipv4;
    }
    InetAddress ipv6 = parseIpv6Literal(host);
    return ipv6 == null ? null : ipv6.getAddress();
  }

  private static byte[] parseIpv4Literal(String host) {
    byte[] octets = new byte[4];
    int part = 0;
    int start = 0;
    for (int i = 0; i <= host.length(); i++) {
      if (i == host.length() || host.charAt(i) == '.') {
        if (part >= 4) {
          return null;
        }
        int len = i - start;
        if (len < 1 || len > 3 || (len > 1 && host.charAt(start) == '0')) {
          return null;
        }
        int value = 0;
        for (int j = start; j < i; j++) {
          char c = host.charAt(j);
          if (c < '0' || c > '9') {
            return null;
          }
          value = value * 10 + (c - '0');
        }
        if (value > 255) {
          return null;
        }
        octets[part++] = (byte) value;
        start = i + 1;
      }
    }
    return part == 4 ? octets : null;
  }

  private static InetAddress parseIpv6Literal(String host) {
    if (host.indexOf(':') < 0) {
      return null;
    }
    for (int i = 0; i < host.length(); i++) {
      char c = host.charAt(i);
      boolean hex =
          (c >= '0' && c <= '9')
              || (c >= 'a' && c <= 'f')
              || (c >= 'A' && c <= 'F')
              || c == ':'
              || c == '.';
      if (!hex) {
        return null;
      }
    }
    try {
      return InetAddress.getByName("[" + host + "]");
    } catch (UnknownHostException invalidLiteral) {
      return null;
    }
  }

  private record HostPort(String host, Integer port) {}
}
