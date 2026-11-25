package app.byteland.ghidra.network;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/** Network host loopback checks and bearer token validation helpers. */
public final class NetworkBinding {
  private NetworkBinding() {}

  /**
   * Ensures a non-blank authentication token is configured when binding or connecting off loopback.
   *
   * @param host target host name or IP literal
   * @param token configured bearer token, or {@code null} when disabled
   */
  public static void requireTokenForNonLoopback(String host, String token) {
    if (isLoopback(host)) return;
    if (token == null || token.isBlank()) {
      throw new IllegalArgumentException("token is required when binding outside loopback");
    }
  }

  /**
   * Checks whether an HTTP {@code Authorization} header matches the expected bearer token in
   * constant time.
   *
   * @param authorizationHeader raw {@code Authorization} header value
   * @param expectedToken expected bearer token value
   * @return {@code true} if the header equals {@code "Bearer " + expectedToken}
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
   * Returns whether every resolved address for {@code host} is a loopback address.
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
