package app.byteland.ghidra.plugin;

import app.byteland.ghidra.agent.AgentConfig;
import app.byteland.ghidra.mcp.McpConfig;
import app.byteland.ghidra.network.NetworkBinding;
import ghidra.framework.options.ToolOptions;
import ghidra.util.bean.opteditor.OptionsVetoException;
import java.util.Objects;

/**
 * Persistent Tool Options settings for the Ghidra Bridge CodeBrowser plugin.
 *
 * <p>Bearer tokens are never stored in Tool Options because project and tool files can be shared.
 */
public record PluginSettings(
    boolean autoStart,
    TransportMode transportMode,
    String host,
    int port,
    String path,
    String toolPrefix,
    boolean autoAttachDaemon) {
  public static final String OPTIONS_CATEGORY = "Ghidra Bridge";
  public static final String OPTION_AUTO_START = "Auto-Start";
  public static final String OPTION_TRANSPORT_MODE = "Transport Mode";
  public static final String OPTION_HOST = "Host";
  public static final String OPTION_PORT = "Port";
  public static final String OPTION_PATH = "Path";
  public static final String OPTION_TOOL_PREFIX = "Tool Prefix";
  public static final String OPTION_AUTO_ATTACH_DAEMON = "Auto-Attach to ghidra-mcp";

  public static final String DEFAULT_HOST = "127.0.0.1";

  public static final int DEFAULT_PORT = McpConfig.DEFAULT_PORT;
  public static final String DEFAULT_MCP_PATH = "/mcp";
  public static final String DEFAULT_WS_PATH = "/ws/agent";
  public static final String DEFAULT_TOOL_PREFIX = McpConfig.DEFAULT_TOOL_PREFIX;

  public enum TransportMode {
    MCP_HTTP,
    WEBSOCKET_SERVER
  }

  public PluginSettings {
    transportMode = transportMode == null ? TransportMode.MCP_HTTP : transportMode;
    host = normalizeLoopbackHost(host);
    AgentConfig.requireValidPort(port);
    String fallbackPath =
        transportMode == TransportMode.MCP_HTTP ? DEFAULT_MCP_PATH : DEFAULT_WS_PATH;
    path = AgentConfig.normalizePath(path, fallbackPath);
    toolPrefix =
        McpConfig.requireToolPrefix(
            toolPrefix == null || toolPrefix.isBlank() ? DEFAULT_TOOL_PREFIX : toolPrefix.trim());
  }

  public static PluginSettings defaults() {
    return new PluginSettings(
        true,
        TransportMode.MCP_HTTP,
        DEFAULT_HOST,
        DEFAULT_PORT,
        DEFAULT_MCP_PATH,
        DEFAULT_TOOL_PREFIX,
        true);
  }

  public static void registerOptions(ToolOptions options) {
    Objects.requireNonNull(options, "options");
    options.registerOption(
        OPTION_AUTO_START,
        true,
        null,
        "Start the local Ghidra Bridge listener automatically when a program opens.");
    options.registerOption(
        OPTION_TRANSPORT_MODE,
        TransportMode.MCP_HTTP,
        null,
        "Select MCP HTTP or embedded WebSocket listener mode.");
    options.registerOption(
        OPTION_HOST,
        DEFAULT_HOST,
        null,
        "Loopback address for the local listener.");
    options.registerOption(
        OPTION_PORT,
        DEFAULT_PORT,
        null,
        "Base TCP port for the local listener. Busy loopback ports increment automatically.");
    options.registerOption(
        OPTION_PATH,
        DEFAULT_MCP_PATH,
        null,
        "HTTP or WebSocket endpoint path for the local listener.");
    options.registerOption(
        OPTION_TOOL_PREFIX,
        DEFAULT_TOOL_PREFIX,
        null,
        "Prefix for MCP tool names exposed by the local MCP HTTP listener.");
    options.registerOption(
        OPTION_AUTO_ATTACH_DAEMON,
        true,
        null,
        "Connect open programs automatically to a local ghidra-mcp daemon when present.");
  }

  public static PluginSettings fromOptions(ToolOptions options) {
    Objects.requireNonNull(options, "options");
    TransportMode mode =
        options.getEnum(OPTION_TRANSPORT_MODE, TransportMode.MCP_HTTP);
    String rawPath = options.getString(OPTION_PATH, DEFAULT_MCP_PATH);
    if (mode == TransportMode.WEBSOCKET_SERVER && DEFAULT_MCP_PATH.equals(rawPath)) {
      rawPath = DEFAULT_WS_PATH;
    }
    return new PluginSettings(
        options.getBoolean(OPTION_AUTO_START, true),
        mode,
        options.getString(OPTION_HOST, DEFAULT_HOST),
        options.getInt(OPTION_PORT, DEFAULT_PORT),
        rawPath,
        options.getString(OPTION_TOOL_PREFIX, DEFAULT_TOOL_PREFIX),
        options.getBoolean(OPTION_AUTO_ATTACH_DAEMON, true));
  }

  public static void validateOptionChange(String optionName, Object newValue)
      throws OptionsVetoException {
    try {
      switch (optionName) {
        case OPTION_HOST -> normalizeLoopbackHost(newValue == null ? null : newValue.toString());
        case OPTION_PORT -> {
          if (!(newValue instanceof Integer portValue)) {
            throw new IllegalArgumentException("port must be an integer");
          }
          AgentConfig.requireValidPort(portValue);
        }
        case OPTION_PATH ->
            AgentConfig.normalizePath(
                newValue == null ? null : newValue.toString(), DEFAULT_MCP_PATH);
        case OPTION_TOOL_PREFIX ->
            McpConfig.requireToolPrefix(newValue == null ? null : newValue.toString().trim());
        default -> {}
      }
    } catch (IllegalArgumentException invalid) {
      throw new OptionsVetoException(invalid.getMessage());
    }
  }

  private static String normalizeLoopbackHost(String rawHost) {
    String normalized = AgentConfig.optionalText(rawHost);
    String candidate = normalized == null ? DEFAULT_HOST : normalized;
    if (!NetworkBinding.isLoopback(candidate)) {
      throw new IllegalArgumentException(
          "Tool Options listeners must bind a loopback address; use Script Manager with token= for"
              + " non-loopback hosts");
    }
    return candidate;
  }
}
