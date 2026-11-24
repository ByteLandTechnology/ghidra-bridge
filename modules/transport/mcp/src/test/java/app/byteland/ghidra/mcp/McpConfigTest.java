package app.byteland.ghidra.mcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import app.byteland.ghidra.network.NetworkBinding;
import java.util.Map;
import org.junit.jupiter.api.Test;

class McpConfigTest {
  @Test
  void appliesDefaultsAndBuildsEndpoint() {
    McpConfig defaults = McpConfig.fromMap(Map.of());
    assertEquals(NetworkBinding.DEFAULT_LOOPBACK_HOST, defaults.host());
    assertEquals(McpConfig.DEFAULT_PORT, defaults.port());
    assertEquals("/mcp", defaults.path());
    assertNull(defaults.token());
    assertEquals("ghidra-bridge", defaults.sessionId());
    assertEquals("ghidra", defaults.toolPrefix());
    assertEquals(
        "http://" + NetworkBinding.DEFAULT_LOOPBACK_HOST + ":8766/mcp",
        defaults.endpoint());
  }

  @Test
  void parsesCustomArgumentsAndAllowsJarOverride() {
    McpConfig custom =
        McpConfig.fromArgs(
            "host=0.0.0.0",
            "port=9100",
            "path=api/mcp",
            "token=s3cr3t",
            "session_id=firmware.bin",
            "tool_prefix=ghidra_2",
            "jar=/opt/ghidra-bridge.jar");
    assertEquals("0.0.0.0", custom.host());
    assertEquals(9100, custom.port());
    assertEquals("/api/mcp", custom.path());
    assertEquals("s3cr3t", custom.token());
    assertEquals("firmware.bin", custom.sessionId());
    assertEquals("ghidra_2", custom.toolPrefix());
    assertEquals("http://0.0.0.0:9100/api/mcp", custom.endpoint());
  }

  @Test
  void rejectsInvalidPortsPrefixesUnknownKeysAndUnauthenticatedNonLoopback() {
    assertEquals(
        "token is required when binding outside loopback",
        assertThrows(IllegalArgumentException.class, () -> McpConfig.fromArgs("host=0.0.0.0"))
            .getMessage());

    assertEquals(
        "port must be in 1..65535",
        assertThrows(IllegalArgumentException.class, () -> McpConfig.fromArgs("port=0"))
            .getMessage());

    assertEquals(
        "port must be an integer",
        assertThrows(IllegalArgumentException.class, () -> McpConfig.fromArgs("port=invalid"))
            .getMessage());

    assertEquals(
        "tool_prefix must start with a letter and contain 1..64 letters, digits, '_', or '-'",
        assertThrows(
                IllegalArgumentException.class,
                () -> McpConfig.fromArgs("tool_prefix=ghidra.bad"))
            .getMessage());

    assertEquals(
        "tool_prefix must start with a letter and contain 1..64 letters, digits, '_', or '-'",
        assertThrows(
                IllegalArgumentException.class,
                () -> McpConfig.fromArgs("tool_prefix=1invalid"))
            .getMessage());

    assertEquals(
        "unknown startup argument: ws_url",
        assertThrows(
                IllegalArgumentException.class,
                () -> McpConfig.fromArgs("ws_url=ws://127.0.0.1:8765/ws/agent"))
            .getMessage());
  }
}
