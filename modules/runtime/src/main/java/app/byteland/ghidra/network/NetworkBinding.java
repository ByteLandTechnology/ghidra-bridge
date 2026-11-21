package app.byteland.ghidra.network;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Validates network host addresses and bearer authentication headers.
 */
public final class NetworkBinding {
  private NetworkBinding() {}

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
    try {
      for (InetAddress address : InetAddress.getAllByName(host.trim())) {
        if (!address.isLoopbackAddress()) return false;
      }
      return true;
    } catch (UnknownHostException error) {
      throw new IllegalArgumentException("host cannot be resolved: " + host, error);
    }
  }
}
