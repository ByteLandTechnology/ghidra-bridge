package app.byteland.ghidra.network;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.util.List;
import org.junit.jupiter.api.Test;

class NetworkBindingTest {

  @Test
  void acceptsMatchingLoopbackHostHeadersAndRejectsRebindingOrDuplicates() throws Exception {
    assertTrue(NetworkBinding.isAllowedHost(List.of("127.0.0.1:8766"), "127.0.0.1", 8766));
    assertTrue(NetworkBinding.isAllowedHost(List.of("127.0.0.2:8766"), "127.0.0.1", 8766));
    assertTrue(NetworkBinding.isAllowedHost(List.of("localhost:8766"), "127.0.0.1", 8766));
    assertTrue(NetworkBinding.isAllowedHost(List.of("LOCALHOST:8766"), "127.0.0.1", 8766));
    assertTrue(NetworkBinding.isAllowedHost(List.of("[::1]:8766"), "127.0.0.1", 8766));
    assertTrue(NetworkBinding.isAllowedHost(List.of("[0:0:0:0:0:0:0:1]:8766"), "::1", 8766));

    assertFalse(NetworkBinding.isAllowedHost((List<String>) null, "127.0.0.1", 8766));
    assertFalse(NetworkBinding.isAllowedHost(List.of(), "127.0.0.1", 8766));
    assertFalse(
        NetworkBinding.isAllowedHost(
            List.of("127.0.0.1:8766", "127.0.0.1:8766"), "127.0.0.1", 8766));
    assertFalse(
        NetworkBinding.isAllowedHost(
            List.of("127.0.0.1:8766", "evil.rebind.example:8766"), "127.0.0.1", 8766));
    assertFalse(NetworkBinding.isAllowedHost(List.of("evil.rebind.example"), "127.0.0.1", 8766));
    assertFalse(
        NetworkBinding.isAllowedHost(List.of("evil.rebind.example:8766"), "127.0.0.1", 8766));
    assertFalse(NetworkBinding.isAllowedHost(List.of("127.0.0.1"), "127.0.0.1", 8766));
    assertFalse(NetworkBinding.isAllowedHost(List.of("127.0.0.1:8765"), "127.0.0.1", 8766));
    assertFalse(NetworkBinding.isAllowedHost(List.of("127.0.0.1:"), "127.0.0.1", 8766));
    assertFalse(NetworkBinding.isAllowedHost(List.of("user@127.0.0.1:8766"), "127.0.0.1", 8766));
    assertFalse(NetworkBinding.isAllowedHost(List.of("127.0.0.1:8766/mcp"), "127.0.0.1", 8766));

    assertTrue(NetworkBinding.isAllowedHost(List.of("127.0.0.1"), "127.0.0.1", 80));
    assertTrue(NetworkBinding.isAllowedHost(List.of("127.0.0.1:80"), "127.0.0.1", 80));
    assertFalse(NetworkBinding.isAllowedHost(List.of("127.0.0.1:8080"), "127.0.0.1", 80));

    assertTrue(NetworkBinding.isAllowedHost(List.of("192.168.1.50:8766"), "192.168.1.50", 8766));
    assertFalse(NetworkBinding.isAllowedHost(List.of("localhost:8766"), "192.168.1.50", 8766));
    assertFalse(
        NetworkBinding.isAllowedHost(List.of("evil.rebind.example:8766"), "192.168.1.50", 8766));

    InetAddress loopback = InetAddress.getByAddress(new byte[] {127, 0, 0, 1});
    InetAddress lan = InetAddress.getByAddress(new byte[] {(byte) 192, (byte) 168, 1, 50});
    assertTrue(
        NetworkBinding.isAllowedHost(List.of("localhost:8766"), "0.0.0.0", 8766, loopback));
    assertTrue(
        NetworkBinding.isAllowedHost(List.of("192.168.1.50:8766"), "0.0.0.0", 8766, lan));
    assertFalse(
        NetworkBinding.isAllowedHost(
            List.of("evil.rebind.example:8766"), "0.0.0.0", 8766, lan));
  }

  @Test
  void acceptsAbsentLoopbackOrConfiguredOriginsAndRejectsExternalOrigins() {
    assertTrue(NetworkBinding.isAllowedOrigin((List<String>) null, "127.0.0.1"));
    assertTrue(NetworkBinding.isAllowedOrigin(List.of(), "127.0.0.1"));
    assertTrue(NetworkBinding.isAllowedOrigin((String) null, "127.0.0.1"));

    assertTrue(NetworkBinding.isAllowedOrigin(List.of("http://127.0.0.1:8766"), "127.0.0.1"));
    assertTrue(NetworkBinding.isAllowedOrigin(List.of("http://localhost:3000"), "127.0.0.1"));
    assertTrue(NetworkBinding.isAllowedOrigin(List.of("https://LOCALHOST"), "127.0.0.1"));
    assertTrue(NetworkBinding.isAllowedOrigin(List.of("http://[::1]:5173"), "127.0.0.1"));
    assertTrue(
        NetworkBinding.isAllowedOrigin(List.of("https://192.168.1.50:8443"), "192.168.1.50"));

    assertFalse(NetworkBinding.isAllowedOrigin(List.of("https://evil.example"), "127.0.0.1"));
    assertFalse(
        NetworkBinding.isAllowedOrigin(List.of("http://evil.rebind.example:8766"), "127.0.0.1"));
    assertFalse(NetworkBinding.isAllowedOrigin(List.of("null"), "127.0.0.1"));
    assertFalse(NetworkBinding.isAllowedOrigin(List.of(""), "127.0.0.1"));
    assertFalse(NetworkBinding.isAllowedOrigin(List.of("   "), "127.0.0.1"));
    assertFalse(NetworkBinding.isAllowedOrigin(List.of("ws://127.0.0.1:8765"), "127.0.0.1"));
    assertFalse(NetworkBinding.isAllowedOrigin(List.of("file:///tmp/test.html"), "127.0.0.1"));
    assertFalse(
        NetworkBinding.isAllowedOrigin(List.of("http://localhost:3000/extra"), "127.0.0.1"));
    assertFalse(NetworkBinding.isAllowedOrigin(List.of("http://localhost:3000?x=1"), "127.0.0.1"));
    assertFalse(NetworkBinding.isAllowedOrigin(List.of("http://user@localhost:3000"), "127.0.0.1"));
    assertFalse(
        NetworkBinding.isAllowedOrigin(
            List.of("http://localhost:3000", "http://localhost:3000"), "127.0.0.1"));
  }
}
