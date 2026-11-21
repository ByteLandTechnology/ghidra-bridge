package app.byteland.ghidra.network;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public final class NetworkBinding {
  private NetworkBinding() {}

  public static void requireTokenForNonLoopback(String host, String token) {
    if (isLoopback(host)) return;
    if (token == null || token.isBlank()) {
      throw new IllegalArgumentException("token is required when binding outside loopback");
    }
  }

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
}
