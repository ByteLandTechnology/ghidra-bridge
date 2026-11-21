package app.byteland.ghidra.network;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/** Validates network bind addresses and HTTP bearer tokens. */
public final class NetworkBinding {
  private NetworkBinding() {}

  /**
   * Requires a non-blank authentication token when {@code host} resolves outside loopback.
   *
   * @param host bind host name or IP address
   * @param token configured bearer token, or {@code null}
   */
  public static void requireTokenForNonLoopback(String host, String token) {
    if (isLoopback(host)) return;
    if (token == null || token.isBlank()) {
      throw new IllegalArgumentException("token is required when binding outside loopback");
    }
  }

  /**
   * Compares an {@code Authorization} header against {@code Bearer <expectedToken>} in constant
   * time.
   *
   * @param authorizationHeader HTTP {@code Authorization} header value, or {@code null}
   * @param expectedToken expected bearer token
   * @return {@code true} when the header matches the expected bearer token
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
   * Reports whether all resolved addresses of {@code host} are loopback addresses.
   *
   * @param host host name or IP address
   * @return {@code true} when every resolved address is a loopback address
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
