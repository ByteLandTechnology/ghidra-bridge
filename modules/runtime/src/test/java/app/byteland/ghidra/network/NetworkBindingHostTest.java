package app.byteland.ghidra.network;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.network.NetworkBinding.HostAuthority;
import app.byteland.ghidra.network.NetworkBinding.HostValidationResult;
import app.byteland.ghidra.network.NetworkBinding.HostValidationStatus;
import java.net.InetAddress;
import java.time.Duration;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class NetworkBindingHostTest {

  @Test
  @DisplayName("Parses valid IPv4, IPv6, and localhost Host authorities with and without ports")
  void parsesValidHostAuthorities() {
    assertEquals(new HostAuthority("127.0.0.1", null), NetworkBinding.parseHostAuthority("127.0.0.1"));
    assertEquals(
        new HostAuthority("127.0.0.1", 8766), NetworkBinding.parseHostAuthority("127.0.0.1:8766"));
    assertEquals(new HostAuthority("[::1]", null), NetworkBinding.parseHostAuthority("[::1]"));
    assertEquals(new HostAuthority("[::1]", 8766), NetworkBinding.parseHostAuthority("[::1]:8766"));
    assertEquals(
        new HostAuthority("[0:0:0:0:0:0:0:1]", 65535),
        NetworkBinding.parseHostAuthority(" [0:0:0:0:0:0:0:1]:65535\t"));
    assertEquals(
        new HostAuthority("[::ffff:127.0.0.1]", 80),
        NetworkBinding.parseHostAuthority("[::ffff:127.0.0.1]:80"));
    assertEquals(
        new HostAuthority("localhost", 18489),
        NetworkBinding.parseHostAuthority("localhost:18489"));
    assertEquals(
        new HostAuthority("rebind.example.invalid", 8766),
        NetworkBinding.parseHostAuthority("rebind.example.invalid:8766"));
  }

  @Test
  @DisplayName("Rejects malformed Host authority values without DNS resolution")
  void rejectsMalformedHostAuthorities() {
    List<String> malformed =
        Arrays.asList(
            null,
            "",
            "   ",
            ":8766",
            "127.0.0.1:",
            "127.0.0.1:0",
            "127.0.0.1:08766",
            "127.0.0.1:65536",
            "127.0.0.1:-1",
            "127.0.0.1:abc",
            "::1",
            "::1:8766",
            "[::1",
            "::1]",
            "[]",
            "[::1]8766",
            "[::1]:",
            "[:::1]:8766",
            "[1::2::3]:8766",
            "[not-ipv6]:8766",
            "[rebind.example.invalid]:8766",
            "user@127.0.0.1:8766",
            "127.0.0.1/mcp",
            "127.0.0.1?x=1",
            "127.0.0.1#frag",
            "127.0.0.1, evil.example",
            "127.0.0.1 evil.example",
            "%6c%6f%63%61%6c%68%6f%73%74",
            ".localhost",
            "-localhost",
            "localhost-",
            "local..host");
    for (String candidate : malformed) {
      assertThrows(
          IllegalArgumentException.class,
          () -> NetworkBinding.parseHostAuthority(candidate),
          "Expected malformed Host rejection for: " + candidate);
    }
  }

  @Test
  @DisplayName("Allows 127.0.0.1, [::1], localhost, and literal config.host() on loopback listeners")
  void allowsValidLoopbackAuthorities() {
    List<String> allowedOnDefaultLoopback =
        List.of(
            "127.0.0.1",
            "127.0.0.1:8766",
            "[::1]",
            "[::1]:8766",
            "localhost",
            "localhost:8766",
            "LOCALHOST",
            "LocalHost:8766");
    for (String header : allowedOnDefaultLoopback) {
      HostValidationResult result =
          NetworkBinding.validateHostHeader(List.of(header), "127.0.0.1", 8766, true);
      assertTrue(result.isValid(), "Expected valid Host for: " + header);
      assertEquals(200, result.httpStatus());
    }

    // Custom loopback literal in 127.0.0.0/8 matches config.host()
    assertTrue(
        NetworkBinding.validateHostHeader(List.of("127.0.0.2:8766"), "127.0.0.2", 8766, true)
            .isValid());

    // Expanded IPv6 loopback matches IPv6 config.host()
    assertTrue(
        NetworkBinding.validateHostHeader(
                List.of("[0:0:0:0:0:0:0:1]:8766"), "::1", 8766, true)
            .isValid());
  }

  @Test
  @DisplayName("Rejects external DNS names, mismatched IPs, and wrong ports on loopback with 403")
  void rejectsDisallowedLoopbackAuthoritiesWith403() {
    List<String> forbiddenOnDefaultLoopback =
        List.of(
            "rebind.example.invalid:8766",
            "rebind.example.invalid",
            "localhost.evil.invalid:8766",
            "127.0.0.1.evil.invalid:8766",
            "localhost.:8766",
            "127.0.0.2:8766",
            "0.0.0.0:8766",
            "[::]:8766",
            "[::ffff:127.0.0.1]:8766",
            "2130706433:8766",
            "0177.0.0.1:8766",
            "0x7f.0.0.1:8766",
            "127.0.0.1:9999",
            "[::1]:9999",
            "localhost:9999");
    for (String header : forbiddenOnDefaultLoopback) {
      HostValidationResult result =
          NetworkBinding.validateHostHeader(List.of(header), "127.0.0.1", 8766, true);
      assertFalse(result.isValid(), "Expected 403 rejection for: " + header);
      assertEquals(HostValidationStatus.FORBIDDEN, result.status());
      assertEquals(403, result.httpStatus());
    }
  }

  @Test
  @DisplayName("Rejects missing, blank, duplicate, and malformed Host headers with 400")
  void rejectsMissingBlankDuplicateAndMalformedWith400() {
    assertEquals(
        400, NetworkBinding.validateHostHeader(null, "127.0.0.1", 8766, true).httpStatus());
    assertEquals(
        400, NetworkBinding.validateHostHeader(List.of(), "127.0.0.1", 8766, true).httpStatus());
    assertEquals(
        400,
        NetworkBinding.validateHostHeader(
                Collections.singletonList(null), "127.0.0.1", 8766, true)
            .httpStatus());
    assertEquals(
        400,
        NetworkBinding.validateHostHeader(List.of("   "), "127.0.0.1", 8766, true).httpStatus());
    assertEquals(
        400,
        NetworkBinding.validateHostHeader(
                List.of("127.0.0.1:8766", "127.0.0.1:8766"), "127.0.0.1", 8766, true)
            .httpStatus());
    assertEquals(
        400,
        NetworkBinding.validateHostHeader(
                List.of("127.0.0.1:8766", "rebind.example.invalid:8766"),
                "127.0.0.1",
                8766,
                true)
            .httpStatus());
    assertEquals(
        400,
        NetworkBinding.validateHostHeader(List.of("[::1"), "127.0.0.1", 8766, true).httpStatus());
  }

  @Test
  @DisplayName("Non-loopback listeners require a single well-formed Host header")
  void validatesNonLoopbackListeners() {
    assertTrue(
        NetworkBinding.validateHostHeader(List.of("ghidra.corp.example:8443"), "0.0.0.0", 8766)
            .isValid());
    assertTrue(
        NetworkBinding.validateHostHeader(List.of("192.168.1.50:8766"), "192.168.1.50", 8766)
            .isValid());
    assertEquals(
        400, NetworkBinding.validateHostHeader(List.of(), "0.0.0.0", 8766).httpStatus());
    assertEquals(
        400,
        NetworkBinding.validateHostHeader(
                List.of("a.example", "b.example"), "0.0.0.0", 8766)
            .httpStatus());
    assertEquals(
        400,
        NetworkBinding.validateHostHeader(List.of("bad host:8766"), "0.0.0.0", 8766).httpStatus());
  }

  @Test
  @DisplayName("Literal IP parsers and Host validation execute with zero DNS lookups")
  void executesWithZeroDnsLookups() {
    assertArrayEquals(new byte[] {127, 0, 0, 1}, NetworkBinding.parseIpv4Literal("127.0.0.1"));
    assertNull(NetworkBinding.parseIpv4Literal("0177.0.0.1"));
    assertNull(NetworkBinding.parseIpv4Literal("2130706433"));
    assertNull(NetworkBinding.parseIpv6Literal("rebind.example.invalid"));
    assertNull(NetworkBinding.parseIpv6Literal("::\uFF11"));

    InetAddress ipv4Loopback = NetworkBinding.parseIpLiteral("127.0.0.1");
    assertNotNull(ipv4Loopback);
    assertTrue(ipv4Loopback.isLoopbackAddress());

    InetAddress ipv6Loopback = NetworkBinding.parseIpLiteral("::1");
    assertNotNull(ipv6Loopback);
    assertTrue(ipv6Loopback.isLoopbackAddress());
    assertEquals(ipv6Loopback, NetworkBinding.parseIpLiteral("0:0:0:0:0:0:0:1"));

    InetAddress mappedLoopback = NetworkBinding.parseIpLiteral("::ffff:127.0.0.1");
    assertNotNull(mappedLoopback);
    assertTrue(mappedLoopback.isLoopbackAddress());

    InetAddress ula = NetworkBinding.parseIpLiteral("fd00::1");
    assertNotNull(ula);
    assertEquals(ula, NetworkBinding.parseIpLiteral("fd00:0:0:0:0:0:0:1"));

    assertNull(NetworkBinding.parseIpLiteral(null));
    assertNull(NetworkBinding.parseIpLiteral(""));
    assertNull(NetworkBinding.parseIpLiteral("127.0.0.1.evil.invalid"));
    assertNull(NetworkBinding.parseIpLiteral("127.0.0.01"));
    assertNull(NetworkBinding.parseIpLiteral("127.1"));
    assertNull(NetworkBinding.parseIpLiteral(":::1"));
    assertNull(NetworkBinding.parseIpLiteral("::1%lo0"));
    assertNull(NetworkBinding.parseIpLiteral("[::1]"));
    assertNull(NetworkBinding.parseIpLiteral("1:2:3:4:5:6::127.0.0.1"));

    org.junit.jupiter.api.Assertions.assertTimeoutPreemptively(
        Duration.ofSeconds(1),
        () -> {
          for (int i = 0; i < 5_000; i++) {
            HostValidationResult res =
                NetworkBinding.validateHostHeader(
                    List.of("rebind-" + i + ".example.invalid:8766"), "127.0.0.1", 8766);
            assertEquals(403, res.httpStatus());
          }
        });
  }
}
