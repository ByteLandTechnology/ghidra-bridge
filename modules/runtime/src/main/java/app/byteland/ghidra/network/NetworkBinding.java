package app.byteland.ghidra.network;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

/**
 * Validates network host addresses and bearer authentication headers.
 */
public final class NetworkBinding {
  private static final int IPV4_BYTE_LENGTH = 4;
  private static final int IPV6_BYTE_LENGTH = 16;
  private static final int MAX_HOST_NAME_LENGTH = 255;
  private static final HostValidationResult VALID_HOST_RESULT =
      new HostValidationResult(HostValidationStatus.VALID, "OK");

  private NetworkBinding() {}

  /** Outcome classification for HTTP {@code Host} header validation. */
  public enum HostValidationStatus {
    /** Header value is syntactically valid and permitted for the listener. */
    VALID,
    /** Header value is absent, duplicate, blank, or malformed. */
    BAD_REQUEST,
    /** Header authority is syntactically valid, yet rejected for a loopback listener. */
    FORBIDDEN
  }

  /**
   * Result of HTTP {@code Host} header validation.
   *
   * @param status validation outcome classification
   * @param message diagnostic status message
   */
  public record HostValidationResult(HostValidationStatus status, String message) {
    /** Validates non-null result fields. */
    public HostValidationResult {
      Objects.requireNonNull(status, "status");
      Objects.requireNonNull(message, "message");
    }

    /**
     * Reports whether the {@code Host} header passed validation.
     *
     * @return {@code true} when {@code status} is {@link HostValidationStatus#VALID}
     */
    public boolean isValid() {
      return status == HostValidationStatus.VALID;
    }

    /**
     * Maps the validation status to an HTTP response status code.
     *
     * @return {@code 200}, {@code 400}, or {@code 403}
     */
    public int httpStatus() {
      return switch (status) {
        case VALID -> 200;
        case BAD_REQUEST -> 400;
        case FORBIDDEN -> 403;
      };
    }
  }

  /**
   * Parsed host and optional TCP port from an HTTP {@code Host} header.
   *
   * @param host host name, IPv4 literal, or bracketed IPv6 literal
   * @param port explicit TCP port in {@code 1..65535}, or {@code null} when absent
   */
  public record HostAuthority(String host, Integer port) {
    /** Validates the host text and optional port range. */
    public HostAuthority {
      if (host == null || host.isBlank()) {
        throw new IllegalArgumentException("host is required");
      }
      if (port != null && (port < 1 || port > 65535)) {
        throw new IllegalArgumentException("port must be in 1..65535");
      }
    }
  }

  /**
   * Requires a non-blank bearer token when the listen host resolves outside loopback.
   *
   * @param host listen host name or IP address
   * @param token configured bearer token, or {@code null}
   */
  public static void requireTokenForNonLoopback(String host, String token) {
    if (isLoopback(host)) return;
    if (token == null || token.isBlank()) {
      throw new IllegalArgumentException("token is required when binding outside loopback");
    }
  }

  /**
   * Requires a non-blank bearer token when a configured origin host resolves outside loopback.
   *
   * @param host origin host name or IP address
   * @param token configured bearer token, or {@code null}
   */
  public static void requireTokenForNonLoopbackOrigin(String host, String token) {
    if (token != null && !token.isBlank()) {
      return;
    }
    boolean loopback;
    try {
      loopback = isLoopback(host);
    } catch (IllegalArgumentException unresolved) {
      loopback = false;
    }
    if (!loopback) {
      throw new IllegalArgumentException(
          "token is required when allowed_origins includes a non-loopback origin");
    }
  }

  /**
   * Compares an HTTP {@code Authorization} header against the expected bearer token in constant
   * time.
   *
   * @param authorizationHeader raw {@code Authorization} header value, or {@code null}
   * @param expectedToken expected bearer token secret
   * @return {@code true} if the header matches {@code Bearer <expectedToken>}
   */
  public static boolean bearerTokenMatches(String authorizationHeader, String expectedToken) {
    if (authorizationHeader == null) {
      return false;
    }
    return MessageDigest.isEqual(
        authorizationHeader.getBytes(StandardCharsets.UTF_8),
        ("Bearer " + expectedToken).getBytes(StandardCharsets.UTF_8));
  }

  /**
   * Reports whether all resolved addresses for a host are loopback addresses.
   *
   * @param host host name or IP literal
   * @return {@code true} if every resolved address is on loopback
   */
  public static boolean isLoopback(String host) {
    if (host == null || host.isBlank()) {
      throw new IllegalArgumentException("host is required");
    }
    InetAddress literal = parseIpLiteral(host);
    if (literal != null) {
      return literal.isLoopbackAddress();
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
   * Validates the inbound HTTP {@code Host} header list for a listener without DNS lookups on the
   * inbound header value.
   *
   * @param hostHeaders inbound {@code Host} header values, or {@code null}
   * @param configuredHost configured listener host name or IP literal
   * @param listenerPort bound listener TCP port in {@code 1..65535}
   * @return validation status and diagnostic message
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
   * Validates the inbound HTTP {@code Host} header list with a precomputed listener loopback flag
   * and zero DNS lookups per request.
   *
   * @param hostHeaders inbound {@code Host} header values, or {@code null}
   * @param configuredHost configured listener host name or IP literal
   * @param listenerPort bound listener TCP port in {@code 1..65535}
   * @param loopbackListener {@code true} when the listener binds to a loopback address
   * @return validation status and diagnostic message
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
   * {@link InetAddress} DNS resolution.
   *
   * @param rawHostHeader raw HTTP {@code Host} header value
   * @return parsed host and optional port
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

  /**
   * Normalizes a host string to lowercase in {@link Locale#ROOT}. Trims ASCII whitespace and
   * removes outer IPv6 brackets when a colon is present.
   *
   * @param host host name or IP literal
   * @return normalized lowercase host string
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
   * Returns {@code true} when {@code host} is {@code localhost} or a literal IPv4/IPv6 loopback
   * address ({@code 127.0.0.0/8}, {@code ::1}, or {@code ::ffff:127.0.0.0/104}). Does not run DNS
   * lookups.
   *
   * @param host candidate host string, or {@code null}
   * @return {@code true} if {@code host} is {@code localhost} or a literal loopback IP address
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
   * Compares two host strings case-insensitively and across canonical IPv4/IPv6 literal forms.
   * Does not run DNS lookups.
   *
   * @param firstHost first host string, or {@code null}
   * @param secondHost second host string, or {@code null}
   * @return {@code true} if both non-empty hosts match syntactically or as IP literals
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
   * Parses a strict IPv4 or IPv6 literal (with optional brackets) into an {@link InetAddress}
   * without DNS resolution. Returns {@code null} if {@code host} is not a valid IP literal.
   *
   * @param host candidate IP literal string, or {@code null}
   * @return parsed {@link InetAddress}, or {@code null} if {@code host} is not a valid IP literal
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
    if (isLiteralLoopbackHost(configuredHost)) {
      return Boolean.TRUE;
    }
    if (parseIpLiteral(configuredHost) != null) {
      return Boolean.FALSE;
    }
    return null;
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
    String normalized = normalizeHost(configuredHost);
    return normalized.indexOf(':') >= 0
        ? parseIpv6Literal(normalized)
        : parseIpv4Literal(normalized);
  }

  /**
   * Parses a strict dotted-quad decimal IPv4 literal into a 4-byte array, or returns {@code null}
   * if invalid. Rejects zero prefixes, short forms, and non-ASCII digits.
   *
   * @param literal candidate IPv4 literal string, or {@code null}
   * @return 4-byte IPv4 address array, or {@code null} if {@code literal} is invalid
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
   * Parses a strict unbracketed IPv6 literal into a 16-byte array, or returns {@code null} if
   * invalid. Accepts {@code ::} zero-compression and an embedded dotted-quad IPv4 suffix, and
   * rejects {@code %} zone IDs.
   *
   * @param literal candidate IPv6 literal string, or {@code null}
   * @return 16-byte IPv6 address array, or {@code null} if {@code literal} is invalid
   */
  public static byte[] parseIpv6Literal(String literal) {
    if (literal == null
        || literal.length() < 2
        || literal.indexOf(':') < 0
        || literal.indexOf('%') >= 0) {
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
