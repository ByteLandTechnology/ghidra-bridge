package app.byteland.ghidra.network;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class NetworkBindingTest {
  @Test
  void parseArgsHandlesBlankEntriesAndEmbeddedEquals() {
    assertEquals(Map.of(), NetworkBinding.parseArgs((String[]) null));
    assertEquals(Map.of(), NetworkBinding.parseArgs("", "   ", null));

    Map<String, String> parsed =
        NetworkBinding.parseArgs(
            " host=127.0.0.1 ", "", "ws_url=ws://127.0.0.1:8765/ws/agent?mode=test&v=1", "token=");
    assertEquals(List.of("host", "ws_url", "token"), List.copyOf(parsed.keySet()));
    assertEquals("127.0.0.1", parsed.get("host"));
    assertEquals("ws://127.0.0.1:8765/ws/agent?mode=test&v=1", parsed.get("ws_url"));
    assertEquals("", parsed.get("token"));
  }

  @Test
  void parseArgsRejectsMalformedAndDuplicateKeys() {
    var missingSeparator =
        assertThrows(IllegalArgumentException.class, () -> NetworkBinding.parseArgs("port"));
    assertEquals("expected key=value argument but got: port", missingSeparator.getMessage());

    var emptyKey =
        assertThrows(IllegalArgumentException.class, () -> NetworkBinding.parseArgs("=8765"));
    assertEquals("expected key=value argument but got: =8765", emptyKey.getMessage());

    var duplicate =
        assertThrows(
            IllegalArgumentException.class,
            () -> NetworkBinding.parseArgs("port=8765", "port=8766"));
    assertEquals("duplicate startup argument: port", duplicate.getMessage());
  }

  @Test
  void rejectUnknownValidatesAllowedStartupKeys() {
    Set<String> allowed = Set.of("host", "port", "jar");
    assertDoesNotThrow(
        () -> NetworkBinding.rejectUnknown(Map.of("host", "127.0.0.1", "jar", "/a.jar"), allowed));

    var error =
        assertThrows(
            IllegalArgumentException.class,
            () -> NetworkBinding.rejectUnknown(Map.of("sessionId", "demo"), allowed));
    assertEquals("unknown startup argument: sessionId", error.getMessage());
  }

  @Test
  void portAndIntegerHelpersEnforceBoundsAndFormat() {
    assertDoesNotThrow(() -> NetworkBinding.requireValidPort(1));
    assertDoesNotThrow(() -> NetworkBinding.requireValidPort(65535));
    assertEquals(
        "port must be in 1..65535",
        assertThrows(IllegalArgumentException.class, () -> NetworkBinding.requireValidPort(0))
            .getMessage());
    assertEquals(
        "port must be in 1..65535",
        assertThrows(IllegalArgumentException.class, () -> NetworkBinding.requireValidPort(65536))
            .getMessage());

    assertNull(NetworkBinding.optionalInteger(null, "port"));
    assertNull(NetworkBinding.optionalInteger("  ", "port"));
    assertEquals(8766, NetworkBinding.optionalInteger(" 8766 ", "port"));

    var invalid =
        assertThrows(
            IllegalArgumentException.class, () -> NetworkBinding.optionalInteger("eight", "port"));
    assertEquals("port must be an integer", invalid.getMessage());
    assertInstanceOf(NumberFormatException.class, invalid.getCause());
  }

  @Test
  void textPathAndSessionFallbackHelpersNormalizeValues() {
    assertNull(NetworkBinding.optionalText(null));
    assertNull(NetworkBinding.optionalText("   "));
    assertEquals("demo", NetworkBinding.optionalText("  demo  "));

    assertEquals("demo", NetworkBinding.requiredText(" demo ", "session_id"));
    assertEquals(
        "session_id is required",
        assertThrows(
                IllegalArgumentException.class,
                () -> NetworkBinding.requiredText(" ", "session_id"))
            .getMessage());

    assertEquals("fallback", NetworkBinding.textOrDefault(null, "fallback"));
    assertEquals("fallback", NetworkBinding.textOrDefault("  ", "fallback"));
    assertEquals("custom", NetworkBinding.textOrDefault(" custom ", "fallback"));

    assertEquals("ghidra-bridge", NetworkBinding.defaultSessionId(null));
    assertEquals("ghidra-bridge", NetworkBinding.defaultSessionId("   "));
    assertEquals("binary.elf", NetworkBinding.defaultSessionId(" binary.elf "));

    assertEquals("/mcp", NetworkBinding.normalizePath(null, "/mcp"));
    assertEquals("/mcp", NetworkBinding.normalizePath("   ", "/mcp"));
    assertEquals("/custom/path", NetworkBinding.normalizePath("custom/path", "/mcp"));
    assertEquals("/already", NetworkBinding.normalizePath(" /already ", "/mcp"));
  }

  @Test
  void bearerTokenMatchesComparesExactHeader() {
    assertTrue(NetworkBinding.bearerTokenMatches("Bearer s3cr3t", "s3cr3t"));
    assertFalse(NetworkBinding.bearerTokenMatches("Bearer wrong", "s3cr3t"));
    assertFalse(NetworkBinding.bearerTokenMatches("s3cr3t", "s3cr3t"));
    assertFalse(NetworkBinding.bearerTokenMatches(null, "s3cr3t"));
    assertFalse(NetworkBinding.bearerTokenMatches("Bearer null", null));
  }

  @Test
  void loopbackAndNonLoopbackChecksEnforceTokenRulesAndSingleResolution() throws Exception {
    assertTrue(NetworkBinding.isLoopback("127.0.0.1"));
    assertTrue(NetworkBinding.isLoopback(" ::1 "));
    assertFalse(NetworkBinding.isLoopback("0.0.0.0"));
    assertFalse(NetworkBinding.isLoopback("192.0.2.10"));

    assertEquals(
        "host is required",
        assertThrows(IllegalArgumentException.class, () -> NetworkBinding.isLoopback(" "))
            .getMessage());

    AtomicInteger lookups = new AtomicInteger();
    NetworkBinding.HostResolver loopbackResolver =
        host -> {
          lookups.incrementAndGet();
          return new InetAddress[] {InetAddress.getByAddress(new byte[] {127, 0, 0, 1})};
        };
    NetworkBinding.requireTokenForNonLoopback("localhost", null, loopbackResolver);
    assertEquals(1, lookups.get());

    InetAddress loopback = InetAddress.getByAddress(new byte[] {127, 0, 0, 1});
    InetAddress lan = InetAddress.getByAddress(new byte[] {(byte) 192, 0, 2, 25});
    AtomicInteger multiHomedLookups = new AtomicInteger();
    NetworkBinding.HostResolver mixedResolver =
        host -> {
          multiHomedLookups.incrementAndGet();
          return new InetAddress[] {loopback, lan};
        };
    var missingToken =
        assertThrows(
            IllegalArgumentException.class,
            () -> NetworkBinding.requireTokenForNonLoopback("dual-host", "  ", mixedResolver));
    assertEquals("token is required when binding outside loopback", missingToken.getMessage());
    assertEquals(1, multiHomedLookups.get());

    assertDoesNotThrow(
        () -> NetworkBinding.requireTokenForNonLoopback("dual-host", "secret", mixedResolver));
    assertEquals(2, multiHomedLookups.get());

    assertFalse(NetworkBinding.isLoopback("empty-host", host -> new InetAddress[0]));

    var unresolved =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                NetworkBinding.isLoopback(
                    "missing.invalid",
                    host -> {
                      throw new UnknownHostException(host);
                    }));
    assertEquals("host cannot be resolved: missing.invalid", unresolved.getMessage());
    assertInstanceOf(UnknownHostException.class, unresolved.getCause());

    assertDoesNotThrow(
        () -> NetworkBinding.requireTokenForNonLoopbackOrigin("localhost", null, loopbackResolver));
    assertEquals(2, lookups.get());

    var nonLoopbackOrigin =
        assertThrows(
            IllegalArgumentException.class,
            () -> NetworkBinding.requireTokenForNonLoopbackOrigin("dual-host", " ", mixedResolver));
    assertEquals(
        "token is required when allowed_origins includes a non-loopback origin",
        nonLoopbackOrigin.getMessage());
    assertDoesNotThrow(() ->
        NetworkBinding.requireTokenForNonLoopbackOrigin(
            "missing.invalid",
            "secret",
            host -> {
              throw new AssertionError("Resolver should not run when token is configured");
            }));
  }

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
