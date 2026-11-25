package app.byteland.ghidra.network;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * Validates loopback host bindings and constant-time bearer token headers.
 */
public final class NetworkBinding {
  private NetworkBinding() {}

  /**
   * Requires a non-blank authentication token whenever {@code host} resolves outside loopback.
   *
   * @param host target bind or endpoint host
   * @param token configured authentication token, or {@code null}
   */
  public static void requireTokenForNonLoopback(String host, String token) {
    if (isLoopback(host)) return;
    if (token == null || token.isBlank()) {
      throw new IllegalArgumentException("token is required when binding outside loopback");
    }
  }

  /**
   * Compares an HTTP {@code Authorization} header against {@code Bearer <expectedToken>} in constant time.
   *
   * @param authorizationHeader raw {@code Authorization} header value, or {@code null}
   * @param expectedToken expected bearer token secret
   * @return {@code true} if the header matches the expected bearer token
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
   * Returns {@code true} when every resolved address for {@code host} is a loopback address.
   *
   * @param host host name or IP literal to resolve
   * @return {@code true} if all resolved addresses are loopback addresses
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
