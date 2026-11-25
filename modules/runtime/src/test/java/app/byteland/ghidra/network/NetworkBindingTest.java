package app.byteland.ghidra.network;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class NetworkBindingTest {

  @Test
  @DisplayName("Normalizes hostnames and strips brackets only around IPv6 literals")
  void normalizesHostAndIpv6Brackets() {
    assertEquals("localhost", NetworkBinding.normalizeHost("  LOCALHOST  "));
    assertEquals("::1", NetworkBinding.normalizeHost(" [::1] "));
    assertEquals("2001:db8::1", NetworkBinding.normalizeHost("[2001:DB8::1]"));
    assertEquals("[localhost]", NetworkBinding.normalizeHost("[localhost]"));
    assertEquals("[127.0.0.1]", NetworkBinding.normalizeHost("[127.0.0.1]"));
  }

  @Test
  @DisplayName("Parses strict IPv4 and IPv6 literals without DNS resolution")
  void parsesValidIpLiteralsAndRejectsMalformedForms() {
    assertArrayEquals(new byte[] {127, 0, 0, 1}, NetworkBinding.parseIpv4Literal("127.0.0.1"));
    assertArrayEquals(new byte[] {127, 0, 0, 2}, NetworkBinding.parseIpv4Literal("127.0.0.2"));
    assertArrayEquals(
        new byte[] {127, (byte) 255, (byte) 255, (byte) 254},
        NetworkBinding.parseIpv4Literal("127.255.255.254"));
    assertNotNull(NetworkBinding.parseIpv6Literal("::1"));
    assertNotNull(NetworkBinding.parseIpv6Literal("0:0:0:0:0:0:0:1"));
    assertNotNull(NetworkBinding.parseIpv6Literal("::ffff:127.0.0.1"));
    assertNotNull(NetworkBinding.parseIpLiteral("[::1]"));
    assertNotNull(NetworkBinding.parseIpLiteral("[2001:DB8::1]"));

    for (String invalid :
        List.of(
            "",
            "127.0.0.01",
            "0177.0.0.1",
            "127.1",
            "2130706433",
            "0x7f.0.0.1",
            "127.0.0.256",
            "127.0.0.1.evil.invalid",
            "[127.0.0.1]",
            ":::1",
            "1::2::3",
            ":1:2:3:4:5:6:7",
            "1:2:3:4:5:6:7:",
            "::1%lo0",
            "[::1%25lo0]",
            "1:2:3:4:5:6::127.0.0.1",
            "127.0.0.1::1",
            "rebind.example.invalid")) {
      assertNull(
          NetworkBinding.parseIpLiteral(invalid),
          "Expected null IP literal for invalid input: " + invalid);
    }
    assertNull(NetworkBinding.parseIpLiteral(null));
    assertNull(NetworkBinding.parseIpv4Literal(null));
    assertNull(NetworkBinding.parseIpv6Literal(null));
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "localhost",
        "LOCALHOST",
        "  LocalHost  ",
        "127.0.0.1",
        "127.0.0.2",
        "127.12.34.56",
        "127.255.255.254",
        "::1",
        "[::1]",
        "0:0:0:0:0:0:0:1",
        "[0:0:0:0:0:0:0:1]",
        "::ffff:127.0.0.1",
        "[::ffff:127.0.0.2]"
      })
  @DisplayName("Recognizes localhost, 127.0.0.0/8, and IPv6 loopback literals")
  void recognizesLiteralLoopbackHosts(String host) {
    assertTrue(NetworkBinding.isLiteralLoopbackHost(host), "Expected loopback literal: " + host);
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "",
        "   ",
        "[localhost]",
        "localhost.evil.invalid",
        "sub.localhost",
        "0.0.0.0",
        "::",
        "[::]",
        "fe80::1",
        "[fe80::1]",
        "192.0.2.10",
        "2001:db8::1",
        "127.0.0.01",
        "127.1",
        "2130706433",
        "::1%lo0",
        "rebind.example.invalid"
      })
  @DisplayName("Rejects non-loopback, wildcard, malformed, and DNS hosts in isLiteralLoopbackHost")
  void rejectsNonLoopbackOrMalformedLiteralHosts(String host) {
    assertFalse(
        NetworkBinding.isLiteralLoopbackHost(host), "Expected non-loopback rejection: " + host);
  }

  @Test
  @DisplayName("Matches hostnames case-insensitively and IPv6 literals canonically without DNS")
  void matchesHostsWithoutDns() {
    assertFalse(NetworkBinding.isLiteralLoopbackHost(null));
    assertFalse(NetworkBinding.hostsMatch(null, "127.0.0.1"));
    assertFalse(NetworkBinding.hostsMatch("127.0.0.1", null));
    assertFalse(NetworkBinding.hostsMatch("   ", "127.0.0.1"));

    assertTrue(NetworkBinding.hostsMatch("ghidra-host.invalid", "GHIDRA-HOST.INVALID"));
    assertFalse(NetworkBinding.hostsMatch("ghidra-host.invalid", "other-host.invalid"));
    assertTrue(NetworkBinding.hostsMatch("2001:db8::1", "[2001:0DB8:0:0:0:0:0:1]"));
    assertFalse(NetworkBinding.hostsMatch("2001:db8::1", "[2001:db8::2]"));

    Assertions.assertTimeoutPreemptively(
        Duration.ofSeconds(1),
        () -> {
          for (int i = 0; i < 5_000; i++) {
            assertFalse(NetworkBinding.isLiteralLoopbackHost("rebind-" + i + ".example.invalid"));
          }
        });
  }
}
