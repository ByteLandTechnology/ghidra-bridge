package app.byteland.ghidra.network;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public final class NetworkBinding {
  private static final int IPV4_BYTE_LENGTH = 4;
  private static final int IPV6_BYTE_LENGTH = 16;
  private static final int IPV6_GROUP_COUNT = 8;
  private static final int MAX_HOST_NAME_LENGTH = 255;
  private static final HostValidationResult VALID_HOST_RESULT =
      new HostValidationResult(HostValidationStatus.VALID, "OK");

  private NetworkBinding() {}

  public enum HostValidationStatus {
    VALID,
    BAD_REQUEST,
    FORBIDDEN
  }

  public record HostValidationResult(HostValidationStatus status, String message) {
    public HostValidationResult {
      Objects.requireNonNull(status, "status");
      Objects.requireNonNull(message, "message");
    }

    public boolean isValid() {
      return status == HostValidationStatus.VALID;
    }

    public int httpStatus() {
      return switch (status) {
        case VALID -> 200;
        case BAD_REQUEST -> 400;
        case FORBIDDEN -> 403;
      };
    }
  }

  public record HostAuthority(String host, Integer port) {
    public HostAuthority {
      if (host == null || host.isBlank()) {
        throw new IllegalArgumentException("host is required");
      }
      if (port != null && (port < 1 || port > 65535)) {
        throw new IllegalArgumentException("port must be in 1..65535");
      }
    }
  }

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
   * Validates the inbound HTTP {@code Host} header list for a listener without performing DNS
   * lookups on the inbound header value.
   */
  public static HostValidationResult validateHostHeader(
      List<String> hostHeaders, String configuredHost, int listenerPort) {
    if (configuredHost == null || configuredHost.isBlank()) {
      throw new IllegalArgumentException("configuredHost is required");
    }
    Boolean fastLoopback = classifyLoopbackWithoutDns(configuredHost);
    boolean loopbackListener = fastLoopback != null ? fastLoopback : isLoopback(configuredHost);
    return validateHostHeader(hostHeaders, configuredHost, listenerPort, loopbackListener);
  }

  /**
   * Validates the inbound HTTP {@code Host} header list with a precomputed listener loopback flag,
   * executing with zero DNS lookups per request.
   */
  public static HostValidationResult validateHostHeader(
      List<String> hostHeaders,
      String configuredHost,
      int listenerPort,
      boolean loopbackListener) {
    if (configuredHost == null || configuredHost.isBlank()) {
      throw new IllegalArgumentException("configuredHost is required");
    }
    if (listenerPort < 1 || listenerPort > 65535) {
      throw new IllegalArgumentException("listenerPort must be in 1..65535");
    }
    if (hostHeaders == null || hostHeaders.isEmpty()) {
      return new HostValidationResult(HostValidationStatus.BAD_REQUEST, "Missing Host header");
    }
    if (hostHeaders.size() > 1) {
      return new HostValidationResult(HostValidationStatus.BAD_REQUEST, "Duplicate Host header");
    }
    String rawHost = hostHeaders.getFirst();
    if (rawHost == null || trimHttpWhitespace(rawHost).isEmpty()) {
      return new HostValidationResult(HostValidationStatus.BAD_REQUEST, "Blank Host header");
    }
    HostAuthority authority;
    try {
      authority = parseHostAuthority(rawHost);
    } catch (IllegalArgumentException invalid) {
      return new HostValidationResult(HostValidationStatus.BAD_REQUEST, "Malformed Host header");
    }
    if (!loopbackListener) {
      return VALID_HOST_RESULT;
    }
    if (authority.port() != null && authority.port() != listenerPort) {
      return new HostValidationResult(HostValidationStatus.FORBIDDEN, "Forbidden Host header");
    }
    if (isAllowedLoopbackAuthorityHost(authority.host(), configuredHost)) {
      return VALID_HOST_RESULT;
    }
    return new HostValidationResult(HostValidationStatus.FORBIDDEN, "Forbidden Host header");
  }

  /**
   * Parses {@code host} and optional {@code :port} from an HTTP {@code Host} header value without
   * performing any {@link InetAddress} DNS resolution.
   */
  public static HostAuthority parseHostAuthority(String rawHostHeader) {
    if (rawHostHeader == null) {
      throw new IllegalArgumentException("Host header is required");
    }
    String trimmed = trimHttpWhitespace(rawHostHeader);
    if (trimmed.isEmpty()) {
      throw new IllegalArgumentException("Host header must not be blank");
    }
    for (int i = 0; i < trimmed.length(); i++) {
      char c = trimmed.charAt(i);
      if (c <= 0x20
          || c >= 0x7F
          || c == '/'
          || c == '\\'
          || c == '?'
          || c == '#'
          || c == '@'
          || c == '%'
          || c == ',') {
        throw new IllegalArgumentException("Malformed Host header");
      }
    }
    if (trimmed.charAt(0) == '[') {
      int closeBracket = trimmed.indexOf(']');
      if (closeBracket <= 1
          || trimmed.indexOf('[', 1) >= 0
          || trimmed.indexOf(']', closeBracket + 1) >= 0) {
        throw new IllegalArgumentException("Malformed IPv6 Host header");
      }
      String ipv6Literal = trimmed.substring(1, closeBracket);
      if (parseIpv6Literal(ipv6Literal) == null) {
        throw new IllegalArgumentException("Invalid IPv6 literal in Host header");
      }
      Integer port = null;
      if (closeBracket + 1 < trimmed.length()) {
        if (trimmed.charAt(closeBracket + 1) != ':') {
          throw new IllegalArgumentException("Malformed port separator in Host header");
        }
        port = parseStrictPort(trimmed.substring(closeBracket + 2));
      }
      return new HostAuthority("[" + ipv6Literal + "]", port);
    }

    if (trimmed.indexOf('[') >= 0 || trimmed.indexOf(']') >= 0) {
      throw new IllegalArgumentException("Malformed bracket in Host header");
    }
    int colon = trimmed.indexOf(':');
    if (colon >= 0 && trimmed.indexOf(':', colon + 1) >= 0) {
      throw new IllegalArgumentException("Unbracketed IPv6 or multiple colons in Host header");
    }
    String hostPart = colon >= 0 ? trimmed.substring(0, colon) : trimmed;
    Integer port = colon >= 0 ? parseStrictPort(trimmed.substring(colon + 1)) : null;
    if (!isValidHostNameOrIpv4(hostPart)) {
      throw new IllegalArgumentException("Malformed host in Host header");
    }
    return new HostAuthority(hostPart, port);
  }

  private static boolean isAllowedLoopbackAuthorityHost(
      String authorityHost, String configuredHost) {
    if ("127.0.0.1".equals(authorityHost)
        || "[::1]".equals(authorityHost)
        || "localhost".equalsIgnoreCase(authorityHost)) {
      return true;
    }
    byte[] inboundIp = parseHostHeaderLiteralIp(authorityHost);
    if (inboundIp == null) {
      return false;
    }
    byte[] configuredIp = parseConfiguredLiteralIp(configuredHost);
    return configuredIp != null && Arrays.equals(inboundIp, configuredIp);
  }

  private static Boolean classifyLoopbackWithoutDns(String configuredHost) {
    String stripped = stripOptionalBrackets(configuredHost.trim());
    if ("localhost".equalsIgnoreCase(stripped)) {
      return Boolean.TRUE;
    }
    byte[] ip = stripped.indexOf(':') >= 0 ? parseIpv6Literal(stripped) : parseIpv4Literal(stripped);
    if (ip == null) {
      return null;
    }
    if (ip.length == IPV4_BYTE_LENGTH) {
      return ip[0] == 127;
    }
    return isIpv6LoopbackBytes(ip);
  }

  private static boolean isIpv6LoopbackBytes(byte[] bytes) {
    boolean leadingZeros10 = true;
    for (int i = 0; i < 10; i++) {
      if (bytes[i] != 0) {
        leadingZeros10 = false;
        break;
      }
    }
    if (!leadingZeros10) {
      return false;
    }
    if (bytes[10] == 0
        && bytes[11] == 0
        && bytes[12] == 0
        && bytes[13] == 0
        && bytes[14] == 0
        && bytes[15] == 1) {
      return true;
    }
    return bytes[10] == (byte) 0xFF && bytes[11] == (byte) 0xFF && bytes[12] == 127;
  }

  private static byte[] parseHostHeaderLiteralIp(String authorityHost) {
    if (authorityHost.length() > 2
        && authorityHost.charAt(0) == '['
        && authorityHost.charAt(authorityHost.length() - 1) == ']') {
      return parseIpv6Literal(authorityHost.substring(1, authorityHost.length() - 1));
    }
    return parseIpv4Literal(authorityHost);
  }

  private static byte[] parseConfiguredLiteralIp(String configuredHost) {
    String stripped = stripOptionalBrackets(configuredHost.trim());
    return stripped.indexOf(':') >= 0 ? parseIpv6Literal(stripped) : parseIpv4Literal(stripped);
  }

  private static String stripOptionalBrackets(String value) {
    if (value.length() >= 2 && value.charAt(0) == '[' && value.charAt(value.length() - 1) == ']') {
      return value.substring(1, value.length() - 1);
    }
    return value;
  }

  static byte[] parseIpv4Literal(String text) {
    if (text == null || text.isEmpty() || text.length() > 15) {
      return null;
    }
    byte[] octets = new byte[IPV4_BYTE_LENGTH];
    int octetIndex = 0;
    int start = 0;
    for (int i = 0; i <= text.length(); i++) {
      if (i == text.length() || text.charAt(i) == '.') {
        if (octetIndex >= IPV4_BYTE_LENGTH) {
          return null;
        }
        int len = i - start;
        if (len < 1 || len > 3) {
          return null;
        }
        if (len > 1 && text.charAt(start) == '0') {
          return null;
        }
        int value = 0;
        for (int j = start; j < i; j++) {
          char c = text.charAt(j);
          if (c < '0' || c > '9') {
            return null;
          }
          value = value * 10 + (c - '0');
        }
        if (value > 255) {
          return null;
        }
        octets[octetIndex++] = (byte) value;
        start = i + 1;
      }
    }
    return octetIndex == IPV4_BYTE_LENGTH ? octets : null;
  }

  static byte[] parseIpv6Literal(String text) {
    if (text == null || text.isEmpty()) {
      return null;
    }
    String working = text;
    if (working.indexOf('.') >= 0) {
      int lastColon = working.lastIndexOf(':');
      if (lastColon < 0) {
        return null;
      }
      byte[] ipv4Tail = parseIpv4Literal(working.substring(lastColon + 1));
      if (ipv4Tail == null) {
        return null;
      }
      String highGroup =
          Integer.toHexString(((ipv4Tail[0] & 0xFF) << 8) | (ipv4Tail[1] & 0xFF));
      String lowGroup =
          Integer.toHexString(((ipv4Tail[2] & 0xFF) << 8) | (ipv4Tail[3] & 0xFF));
      working = working.substring(0, lastColon + 1) + highGroup + ":" + lowGroup;
    }

    int doubleColon = working.indexOf("::");
    String[] leftGroups;
    String[] rightGroups;
    if (doubleColon >= 0) {
      if (working.indexOf("::", doubleColon + 1) >= 0) {
        return null;
      }
      String left = working.substring(0, doubleColon);
      String right = working.substring(doubleColon + 2);
      leftGroups = left.isEmpty() ? new String[0] : left.split(":", -1);
      rightGroups = right.isEmpty() ? new String[0] : right.split(":", -1);
      if (leftGroups.length + rightGroups.length >= IPV6_GROUP_COUNT) {
        return null;
      }
    } else {
      leftGroups = working.split(":", -1);
      rightGroups = new String[0];
      if (leftGroups.length != IPV6_GROUP_COUNT) {
        return null;
      }
    }

    byte[] bytes = new byte[IPV6_BYTE_LENGTH];
    for (int i = 0; i < leftGroups.length; i++) {
      int groupValue = parseHexGroup16(leftGroups[i]);
      if (groupValue < 0) {
        return null;
      }
      bytes[i * 2] = (byte) ((groupValue >>> 8) & 0xFF);
      bytes[i * 2 + 1] = (byte) (groupValue & 0xFF);
    }
    int rightStartGroup = IPV6_GROUP_COUNT - rightGroups.length;
    for (int i = 0; i < rightGroups.length; i++) {
      int groupValue = parseHexGroup16(rightGroups[i]);
      if (groupValue < 0) {
        return null;
      }
      int byteOffset = (rightStartGroup + i) * 2;
      bytes[byteOffset] = (byte) ((groupValue >>> 8) & 0xFF);
      bytes[byteOffset + 1] = (byte) (groupValue & 0xFF);
    }
    return bytes;
  }

  private static int parseHexGroup16(String group) {
    if (group.isEmpty() || group.length() > 4) {
      return -1;
    }
    int value = 0;
    for (int i = 0; i < group.length(); i++) {
      int digit = Character.digit(group.charAt(i), 16);
      if (digit < 0) {
        return -1;
      }
      value = (value << 4) | digit;
    }
    return value;
  }

  private static boolean isValidHostNameOrIpv4(String hostPart) {
    if (hostPart.isEmpty() || hostPart.length() > MAX_HOST_NAME_LENGTH) {
      return false;
    }
    char first = hostPart.charAt(0);
    char last = hostPart.charAt(hostPart.length() - 1);
    if (first == '.' || first == '-' || last == '-') {
      return false;
    }
    char previous = 0;
    for (int i = 0; i < hostPart.length(); i++) {
      char c = hostPart.charAt(i);
      boolean allowed =
          (c >= 'A' && c <= 'Z')
              || (c >= 'a' && c <= 'z')
              || (c >= '0' && c <= '9')
              || c == '-'
              || c == '.'
              || c == '_';
      if (!allowed) {
        return false;
      }
      if ((c == '.' && (previous == '.' || previous == '-')) || (c == '-' && previous == '.')) {
        return false;
      }
      previous = c;
    }
    return true;
  }

  private static int parseStrictPort(String portText) {
    if (portText.isEmpty() || portText.length() > 5 || portText.charAt(0) == '0') {
      throw new IllegalArgumentException("Malformed port in Host header");
    }
    int port = 0;
    for (int i = 0; i < portText.length(); i++) {
      char c = portText.charAt(i);
      if (c < '0' || c > '9') {
        throw new IllegalArgumentException("Malformed port in Host header");
      }
      port = port * 10 + (c - '0');
    }
    if (port < 1 || port > 65535) {
      throw new IllegalArgumentException("Port out of range in Host header");
    }
    return port;
  }

  private static String trimHttpWhitespace(String value) {
    int start = 0;
    int end = value.length();
    while (start < end && (value.charAt(start) == ' ' || value.charAt(start) == '\t')) {
      start++;
    }
    while (end > start && (value.charAt(end - 1) == ' ' || value.charAt(end - 1) == '\t')) {
      end--;
    }
    return value.substring(start, end);
  }
}
