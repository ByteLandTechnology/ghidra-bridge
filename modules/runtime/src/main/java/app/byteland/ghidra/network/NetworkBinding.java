package app.byteland.ghidra.network;

import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;

public final class NetworkBinding {
  private static final int IPV4_OCTETS = 4;
  private static final int MAX_PORT = 65535;
  private static final int DEFAULT_HTTP_PORT = 80;

  private NetworkBinding() {}

  public static void requireTokenForNonLoopback(String host, String token) {
    if (isLoopback(host)) return;
    if (token == null || token.isBlank()) {
      throw new IllegalArgumentException("token is required when binding outside loopback");
    }
  }

  public static boolean bearerTokenMatches(String authorizationHeader, String expectedToken) {
    if (authorizationHeader == null) {
      return false;
    }
    return MessageDigest.isEqual(
        authorizationHeader.getBytes(StandardCharsets.UTF_8),
        ("Bearer " + expectedToken).getBytes(StandardCharsets.UTF_8));
  }

  public static boolean isLoopback(String host) {
    if (host == null || host.isBlank()) {
      throw new IllegalArgumentException("host is required");
    }
    try {
      for (InetAddress address : InetAddress.getAllByName(host.trim())) {
        if (!address.isLoopbackAddress()) return false;
      }
      return true;
    } catch (UnknownHostException error) {
      throw new IllegalArgumentException("host cannot be resolved: " + host, error);
    }
  }

  /**
   * Returns {@code true} when {@code hostHeaders} has one value for the bound listener.
   */
  public static boolean isAllowedHost(
      List<String> hostHeaders, String configuredHost, int boundPort) {
    return isAllowedHost(hostHeaders, configuredHost, boundPort, null);
  }

  /**
   * Returns {@code true} when {@code hostHeaders} has one value for the bound listener.
   */
  public static boolean isAllowedHost(
      List<String> hostHeaders,
      String configuredHost,
      int boundPort,
      InetAddress localAddress) {
    if (hostHeaders == null || hostHeaders.size() != 1) {
      return false;
    }
    return isAllowedHost(hostHeaders.getFirst(), configuredHost, boundPort, localAddress);
  }

  /**
   * Returns {@code true} when {@code hostHeader} names the bound listener host and port.
   */
  public static boolean isAllowedHost(String hostHeader, String configuredHost, int boundPort) {
    return isAllowedHost(hostHeader, configuredHost, boundPort, null);
  }

  /**
   * Returns {@code true} when {@code hostHeader} names the bound listener host and port.
   * Domain names from the request never use DNS, which stops DNS rebinding.
   */
  public static boolean isAllowedHost(
      String hostHeader, String configuredHost, int boundPort, InetAddress localAddress) {
    if (hostHeader == null
        || hostHeader.isBlank()
        || configuredHost == null
        || configuredHost.isBlank()
        || boundPort < 1
        || boundPort > MAX_PORT) {
      return false;
    }
    String trimmed = hostHeader.trim();
    if (containsForbiddenAuthorityChars(trimmed) || hasEmptyPort(trimmed)) {
      return false;
    }
    URI uri;
    try {
      uri = new URI("http://" + trimmed);
    } catch (URISyntaxException invalidHost) {
      return false;
    }
    if (uri.getRawUserInfo() != null
        || uri.getHost() == null
        || !uri.getRawPath().isEmpty()
        || uri.getRawQuery() != null
        || uri.getRawFragment() != null) {
      return false;
    }
    int port = uri.getPort();
    if (port != boundPort && !(port == -1 && boundPort == DEFAULT_HTTP_PORT)) {
      return false;
    }
    String requestHost = stripBrackets(uri.getHost());
    String expectedHost = stripBrackets(configuredHost.trim());
    InetAddress requestIp = tryParseUriHostIpLiteral(uri.getHost());
    InetAddress expectedIp = tryParseHostIpLiteral(expectedHost);
    if (requestHost.equalsIgnoreCase(expectedHost)) {
      return true;
    }
    if (requestIp != null && expectedIp != null && requestIp.equals(expectedIp)) {
      return true;
    }
    if (isConfiguredLoopback(expectedHost, expectedIp)
        && isLoopbackHostLiteralOrLocalhost(requestHost, requestIp)) {
      return true;
    }
    if (expectedIp != null && expectedIp.isAnyLocalAddress() && localAddress != null) {
      if (requestIp != null && requestIp.equals(localAddress)) {
        return true;
      }
      return localAddress.isLoopbackAddress()
          && isLoopbackHostLiteralOrLocalhost(requestHost, requestIp);
    }
    return false;
  }

  /**
   * Returns {@code true} when {@code originHeaders} is absent or has one permitted origin.
   */
  public static boolean isAllowedOrigin(List<String> originHeaders, String configuredHost) {
    if (originHeaders == null || originHeaders.isEmpty()) {
      return true;
    }
    if (originHeaders.size() != 1) {
      return false;
    }
    return isAllowedOrigin(originHeaders.getFirst(), configuredHost);
  }

  /**
   * Returns {@code true} when {@code originHeader} is {@code null}, or is an {@code http} or
   * {@code https} origin on a loopback host or {@code configuredHost}.
   */
  public static boolean isAllowedOrigin(String originHeader, String configuredHost) {
    if (originHeader == null) {
      return true;
    }
    if (configuredHost == null || configuredHost.isBlank()) {
      return false;
    }
    String trimmed = originHeader.trim();
    if (trimmed.isEmpty() || containsWhitespace(trimmed)) {
      return false;
    }
    URI uri;
    try {
      uri = new URI(trimmed);
    } catch (URISyntaxException invalidOrigin) {
      return false;
    }
    String scheme = uri.getScheme();
    if (scheme == null
        || (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme))) {
      return false;
    }
    if (uri.getRawUserInfo() != null
        || uri.getHost() == null
        || uri.getRawAuthority() == null
        || hasEmptyPort(uri.getRawAuthority())
        || !uri.getRawPath().isEmpty()
        || uri.getRawQuery() != null
        || uri.getRawFragment() != null) {
      return false;
    }
    int port = uri.getPort();
    if (port != -1 && (port < 1 || port > MAX_PORT)) {
      return false;
    }
    String originHost = stripBrackets(uri.getHost());
    String expectedHost = stripBrackets(configuredHost.trim());
    InetAddress originIp = tryParseUriHostIpLiteral(uri.getHost());
    InetAddress expectedIp = tryParseHostIpLiteral(expectedHost);
    if (isLoopbackHostLiteralOrLocalhost(originHost, originIp)) {
      return true;
    }
    if (originHost.equalsIgnoreCase(expectedHost)) {
      return true;
    }
    return originIp != null && expectedIp != null && originIp.equals(expectedIp);
  }

  private static boolean isConfiguredLoopback(String expectedHost, InetAddress expectedIp) {
    if ("localhost".equalsIgnoreCase(expectedHost)) {
      return true;
    }
    if (expectedIp != null) {
      return expectedIp.isLoopbackAddress();
    }
    try {
      return isLoopback(expectedHost);
    } catch (IllegalArgumentException unresolvable) {
      return false;
    }
  }

  private static boolean isLoopbackHostLiteralOrLocalhost(String host, InetAddress ipLiteral) {
    return "localhost".equalsIgnoreCase(host)
        || (ipLiteral != null && ipLiteral.isLoopbackAddress());
  }

  private static InetAddress tryParseUriHostIpLiteral(String uriHost) {
    if (uriHost.startsWith("[") && uriHost.endsWith("]")) {
      if (uriHost.indexOf('%') >= 0) {
        return null;
      }
      try {
        return InetAddress.getByName(uriHost);
      } catch (UnknownHostException invalidIpv6) {
        return null;
      }
    }
    return tryParseIpv4Literal(uriHost);
  }

  private static InetAddress tryParseHostIpLiteral(String host) {
    if (host.indexOf(':') >= 0) {
      return tryParseUriHostIpLiteral("[" + stripBrackets(host) + "]");
    }
    return tryParseIpv4Literal(host);
  }

  private static InetAddress tryParseIpv4Literal(String host) {
    byte[] octets = new byte[IPV4_OCTETS];
    int partIndex = 0;
    int start = 0;
    for (int i = 0; i <= host.length(); i++) {
      if (i == host.length() || host.charAt(i) == '.') {
        if (partIndex >= IPV4_OCTETS) {
          return null;
        }
        int length = i - start;
        if (length < 1 || length > 3) {
          return null;
        }
        if (length > 1 && host.charAt(start) == '0') {
          return null;
        }
        int value = 0;
        for (int j = start; j < i; j++) {
          char ch = host.charAt(j);
          if (ch < '0' || ch > '9') {
            return null;
          }
          value = value * 10 + (ch - '0');
        }
        if (value > 255) {
          return null;
        }
        octets[partIndex++] = (byte) value;
        start = i + 1;
      }
    }
    if (partIndex != IPV4_OCTETS) {
      return null;
    }
    try {
      return InetAddress.getByAddress(octets);
    } catch (UnknownHostException impossible) {
      return null;
    }
  }

  private static String stripBrackets(String host) {
    if (host.length() >= 2 && host.startsWith("[") && host.endsWith("]")) {
      return host.substring(1, host.length() - 1);
    }
    return host;
  }

  private static boolean containsForbiddenAuthorityChars(String value) {
    for (int i = 0; i < value.length(); i++) {
      char ch = value.charAt(i);
      if (Character.isWhitespace(ch)
          || ch == '@'
          || ch == '/'
          || ch == '?'
          || ch == '#'
          || ch == '\\') {
        return true;
      }
    }
    return false;
  }

  private static boolean containsWhitespace(String value) {
    for (int i = 0; i < value.length(); i++) {
      if (Character.isWhitespace(value.charAt(i))) {
        return true;
      }
    }
    return false;
  }

  private static boolean hasEmptyPort(String authority) {
    return authority.endsWith(":");
  }
}
