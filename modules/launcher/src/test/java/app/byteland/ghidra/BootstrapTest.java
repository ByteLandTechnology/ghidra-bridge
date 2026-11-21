package app.byteland.ghidra;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ghidra.program.model.listing.Program;
import java.lang.reflect.Proxy;
import java.util.Base64;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class BootstrapTest {

  @Test
  @DisplayName("resolveConfig generates a 256-bit URL-safe base64 token when token is omitted in server mode")
  void resolveConfigGeneratesRandomTokenWhenOmitted() {
    Program program = stubProgram("sample.elf");
    Bootstrap.EffectiveConfig first = Bootstrap.resolveConfig(new String[0], program);
    Bootstrap.EffectiveConfig second = Bootstrap.resolveConfig(new String[0], program);

    assertTrue(first.tokenGenerated());
    assertNotNull(first.config().token());
    assertEquals(32, Base64.getUrlDecoder().decode(first.config().token()).length);
    assertFalse(first.config().token().contains("="));
    assertNotEquals(first.config().token(), second.config().token());
    assertEquals("127.0.0.1", first.config().host());
    assertEquals(8765, first.config().port());
    assertEquals("sample.elf", first.config().sessionId());
    for (String defaultMsg : first.defaultMessages()) {
      assertFalse(defaultMsg.contains(first.config().token()));
    }
  }

  @Test
  @DisplayName("resolveConfig preserves explicit token and leaves outbound token optional")
  void resolveConfigPreservesExplicitAndOutboundModes() {
    Program program = stubProgram("sample.elf");
    Bootstrap.EffectiveConfig explicit =
        Bootstrap.resolveConfig(new String[] {"token=custom-secret"}, program);
    assertFalse(explicit.tokenGenerated());
    assertEquals("custom-secret", explicit.config().token());

    Bootstrap.EffectiveConfig outbound =
        Bootstrap.resolveConfig(new String[] {"ws_url=ws://127.0.0.1:8765/ws/agent"}, program);
    assertFalse(outbound.tokenGenerated());
    assertTrue(outbound.config().isOutboundMode());
    assertNull(outbound.config().token());

    assertThrows(
        IllegalArgumentException.class,
        () -> Bootstrap.resolveConfig(new String[] {"token="}, program));
  }

  @Test
  @DisplayName("resolveMcpConfig generates a 256-bit URL-safe base64 token when token is omitted")
  void resolveMcpConfigGeneratesRandomTokenWhenOmitted() {
    Program program = stubProgram("sample.elf");
    Bootstrap.EffectiveMcpConfig generated = Bootstrap.resolveMcpConfig(new String[0], program);
    assertTrue(generated.tokenGenerated());
    assertNotNull(generated.config().token());
    assertEquals(32, Base64.getUrlDecoder().decode(generated.config().token()).length);
    assertEquals("127.0.0.1", generated.config().host());
    assertEquals(8766, generated.config().port());
    assertEquals("sample.elf", generated.config().sessionId());

    Bootstrap.EffectiveMcpConfig explicit =
        Bootstrap.resolveMcpConfig(new String[] {"token=mcp-explicit"}, program);
    assertFalse(explicit.tokenGenerated());
    assertEquals("mcp-explicit", explicit.config().token());

    assertThrows(
        IllegalArgumentException.class,
        () -> Bootstrap.resolveMcpConfig(new String[] {"token="}, program));
  }

  private static Program stubProgram(String name) {
    return (Program)
        Proxy.newProxyInstance(
            Program.class.getClassLoader(),
            new Class<?>[] {Program.class},
            (proxy, method, args) -> {
              if ("getName".equals(method.getName())) {
                return name;
              }
              throw new UnsupportedOperationException(method.getName());
            });
  }
}
