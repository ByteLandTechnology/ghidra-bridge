package app.byteland.ghidra;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ghidra.app.script.GhidraScript;
import ghidra.app.services.ConsoleService;
import ghidra.program.model.listing.Program;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class BootstrapTest {

  static final class RecordingScript extends GhidraScript {
    final List<String> logLines = new ArrayList<>();

    @Override
    protected void run() {}

    @Override
    public void println(String message) {
      logLines.add(message);
    }
  }

  @Test
  @DisplayName("resolveConfig generates a 256-bit URL-safe session token when omitted in server mode")
  void testResolveConfigGenerates256BitUrlSafeTokenWhenOmitted() {
    Program program = stubProgram("target.bin");

    Bootstrap.EffectiveConfig first = Bootstrap.resolveConfig(new String[0], program);
    Bootstrap.EffectiveConfig second = Bootstrap.resolveConfig(new String[] {"port=9001"}, program);

    assertNotNull(first.generatedToken());
    assertEquals(first.generatedToken(), first.config().token());
    assertEquals("127.0.0.1", first.config().host());
    assertEquals(8765, first.config().port());
    assertEquals("target.bin", first.config().sessionId());

    byte[] decoded = Base64.getUrlDecoder().decode(first.generatedToken());
    assertEquals(32, decoded.length);
    assertTrue(first.generatedToken().matches("[A-Za-z0-9_-]{43}"));

    assertNotNull(second.generatedToken());
    assertNotEquals(first.generatedToken(), second.generatedToken());

    // Default log messages must redact the generated token.
    assertTrue(first.defaultMessages().contains("token=<generated>"));
    assertTrue(
        first.defaultMessages().stream().noneMatch(msg -> msg.contains(first.generatedToken())));
  }

  @Test
  @DisplayName("resolveConfig preserves explicit token, rejects blank token, and leaves outbound token optional")
  void testResolveConfigExplicitBlankAndOutboundTokens() {
    Program program = stubProgram("target.bin");

    Bootstrap.EffectiveConfig configured =
        Bootstrap.resolveConfig(new String[] {"token=explicit-secret"}, program);
    assertNull(configured.generatedToken());
    assertEquals("explicit-secret", configured.config().token());
    assertFalse(configured.defaultMessages().contains("token=<generated>"));

    assertThrows(
        IllegalArgumentException.class,
        () -> Bootstrap.resolveConfig(new String[] {"token="}, program));
    assertThrows(
        IllegalArgumentException.class,
        () -> Bootstrap.resolveConfig(new String[] {"token=   "}, program));

    Bootstrap.EffectiveConfig outbound =
        Bootstrap.resolveConfig(new String[] {"ws_url=ws://127.0.0.1:8765/ws/agent"}, program);
    assertNull(outbound.generatedToken());
    assertNull(outbound.config().token());
    assertTrue(outbound.config().isOutboundMode());
  }

  @Test
  @DisplayName("reportServerAuthToken prints generated token only to ConsoleService and never to script.println")
  void testReportServerAuthTokenWritesOnlyToConsoleService() {
    String generated = Bootstrap.generateSessionToken();
    RecordingScript guiScript = new RecordingScript();
    List<String> consoleLines = new ArrayList<>();
    ConsoleService consoleService = stubConsoleService(consoleLines);

    assertTrue(Bootstrap.reportServerAuthToken(guiScript, consoleService, null, generated));
    assertEquals(
        List.of("[ghidra-bridge]   Session Token: " + generated), consoleLines);
    assertEquals(
        List.of("[ghidra-bridge]   Auth Token: generated (printed to console)"),
        guiScript.logLines);
    assertTrue(guiScript.logLines.stream().noneMatch(line -> line.contains(generated)));

    // Without GUI ConsoleService or interactive System.console(), token is never written to logs.
    RecordingScript headlessScript = new RecordingScript();
    assertFalse(Bootstrap.reportServerAuthToken(headlessScript, null, null, generated));
    assertTrue(headlessScript.logLines.stream().noneMatch(line -> line.contains(generated)));

    // Configured tokens are never printed to either ConsoleService or script.println.
    RecordingScript configuredScript = new RecordingScript();
    List<String> configuredConsoleLines = new ArrayList<>();
    assertTrue(
        Bootstrap.reportServerAuthToken(
            configuredScript, stubConsoleService(configuredConsoleLines), null, null));
    assertTrue(configuredConsoleLines.isEmpty());
    assertEquals(
        List.of("[ghidra-bridge]   Auth Token: configured"), configuredScript.logLines);
  }

  private static Program stubProgram(String name) {
    return (Program)
        Proxy.newProxyInstance(
            Program.class.getClassLoader(),
            new Class<?>[] {Program.class},
            (proxy, method, args) -> "getName".equals(method.getName()) ? name : null);
  }

  private static ConsoleService stubConsoleService(List<String> lines) {
    return (ConsoleService)
        Proxy.newProxyInstance(
            ConsoleService.class.getClassLoader(),
            new Class<?>[] {ConsoleService.class},
            (proxy, method, args) -> {
              if ("println".equals(method.getName()) && args != null && args.length == 1) {
                lines.add((String) args[0]);
              }
              return null;
            });
  }
}
