package app.byteland.ghidra;

import app.byteland.ghidra.agent.AgentConfig;
import app.byteland.ghidra.agent.AgentWebSocketServer;
import app.byteland.ghidra.mcp.McpConfig;
import docking.DockingWindowManager;
import docking.widgets.values.AbstractValue;
import docking.widgets.values.GValuesMap;
import docking.widgets.values.StringValue;
import docking.widgets.values.ValuesMapDialog;
import ghidra.program.model.listing.Program;
import ghidra.util.MessageType;
import ghidra.util.Swing;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.IntPredicate;
import javax.swing.JComponent;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

/**
 * Interactive GUI configuration dialogs and multi-tab default calculation for {@link Bootstrap}.
 */
final class GuiConfigDialog {
  static final String DEFAULT_HOST = "127.0.0.1";

  static final int DEFAULT_WS_PORT = 8765;
  static final String DEFAULT_WS_PATH = AgentWebSocketServer.DEFAULT_PATH;
  static final int DEFAULT_MCP_PORT = McpConfig.DEFAULT_PORT;
  static final String DEFAULT_MCP_PATH = "/mcp";

  static final String HOST_KEY = "host";
  static final String PORT_KEY = "port";
  static final String PATH_KEY = "path";
  static final String SESSION_ID_KEY = "session_id";
  static final String TOKEN_KEY = "token";
  static final String WS_URL_KEY = "ws_url";
  static final String EXIT_DEADLINE_KEY = "exit_deadline_sec";
  static final String TOOL_PREFIX_KEY = "tool_prefix";

  private static final int FIELD_COLUMNS = 28;
  private static final int MAX_PORT = 65535;
  private static final int MAX_TOOL_PREFIX_LENGTH = 64;

  private static final Set<String> ACTIVE_SESSION_IDS = ConcurrentHashMap.newKeySet();
  private static final Set<String> ACTIVE_MCP_TOOL_PREFIXES = ConcurrentHashMap.newKeySet();

  private static volatile DialogPresenter presenter = GuiConfigDialog::showDockingDialog;

  @FunctionalInterface
  interface DialogPresenter {
    /**
     * Presents {@code dialog} and returns {@code true} if accepted or {@code false} if canceled.
     */
    boolean show(String kind, ValuesMapDialog dialog);
  }

  record WebSocketDefaults(String host, int port, String path, String sessionId) {}

  record McpDefaults(String host, int port, String path, String sessionId, String toolPrefix) {}

  private GuiConfigDialog() {}

  static void setPresenterForTesting(DialogPresenter customPresenter) {
    presenter =
        customPresenter == null ? GuiConfigDialog::showDockingDialog : customPresenter;
  }

  static void resetForTesting() {
    presenter = GuiConfigDialog::showDockingDialog;
    ACTIVE_SESSION_IDS.clear();
    ACTIVE_MCP_TOOL_PREFIXES.clear();
  }

  static SessionLease registerActiveSession(String sessionId, String mcpToolPrefix) {
    boolean addedSession = sessionId != null && ACTIVE_SESSION_IDS.add(sessionId);
    boolean addedPrefix = mcpToolPrefix != null && ACTIVE_MCP_TOOL_PREFIXES.add(mcpToolPrefix);
    return new SessionLease(
        addedSession ? sessionId : null, addedPrefix ? mcpToolPrefix : null);
  }

  static Optional<AgentConfig> promptWebSocket(Program program) {
    WebSocketDefaults defaults = computeWebSocketDefaults(program);
    DialogPresenter activePresenter = presenter;
    return Swing.runNow(
        () -> {
          ValuesMapDialog dialog = createWebSocketDialog(program, defaults);
          if (!activePresenter.show("websocket", dialog) || dialog.isCancelled()) {
            return Optional.empty();
          }
          GValuesMap values = dialog.getValues();
          if (values == null) {
            return Optional.empty();
          }
          return Optional.of(parseWebSocketValues(values, defaults));
        });
  }

  static Optional<McpConfig> promptMcp(Program program) {
    McpDefaults defaults = computeMcpDefaults(program);
    DialogPresenter activePresenter = presenter;
    return Swing.runNow(
        () -> {
          ValuesMapDialog dialog = createMcpDialog(program, defaults);
          if (!activePresenter.show("mcp", dialog) || dialog.isCancelled()) {
            return Optional.empty();
          }
          GValuesMap values = dialog.getValues();
          if (values == null) {
            return Optional.empty();
          }
          return Optional.of(parseMcpValues(values));
        });
  }

  static ValuesMapDialog createWebSocketDialog(Program program, WebSocketDefaults defaults) {
    Objects.requireNonNull(defaults, "defaults");
    String programLabel = displayProgramName(program);
    GValuesMap values = new BridgeValuesMap();

    TextValue hostValue = new TextValue(HOST_KEY, defaults.host());
    TextValue portValue = new TextValue(PORT_KEY, Integer.toString(defaults.port()));
    TextValue pathValue = new TextValue(PATH_KEY, defaults.path());
    TextValue sessionIdValue = new TextValue(SESSION_ID_KEY, defaults.sessionId());
    SecretValue tokenValue = new SecretValue(TOKEN_KEY, "");
    TextValue wsUrlValue = new TextValue(WS_URL_KEY, "");
    TextValue exitDeadlineValue = new TextValue(EXIT_DEADLINE_KEY, "");

    values.addValue(hostValue);
    values.addValue(portValue);
    values.addValue(pathValue);
    values.addValue(sessionIdValue);
    values.addValue(tokenValue);
    values.addValue(wsUrlValue);
    values.addValue(exitDeadlineValue);

    values.setValidator(
        (map, statusListener) -> {
          try {
            parseWebSocketValues(map, defaults);
            return true;
          } catch (IllegalArgumentException invalid) {
            if (statusListener != null) {
              statusListener.setStatusText(invalid.getMessage(), MessageType.ERROR);
            }
            return false;
          }
        });

    ValuesMapDialog dialog =
        new ValuesMapDialog(
            "Ghidra Bridge - WebSocket Configuration",
            "Configure the WebSocket JSON-RPC 2.0 bridge for "
                + programLabel
                + ". Leave ws_url blank to start an embedded server, or enter ws_url for outbound"
                + " client mode.",
            values);

    bindOutboundModeFieldState(wsUrlValue, hostValue, portValue, pathValue);
    return dialog;
  }

  static ValuesMapDialog createMcpDialog(Program program, McpDefaults defaults) {
    Objects.requireNonNull(defaults, "defaults");
    String programLabel = displayProgramName(program);
    GValuesMap values = new BridgeValuesMap();

    values.addValue(new TextValue(HOST_KEY, defaults.host()));
    values.addValue(new TextValue(PORT_KEY, Integer.toString(defaults.port())));
    values.addValue(new TextValue(PATH_KEY, defaults.path()));
    values.addValue(new TextValue(SESSION_ID_KEY, defaults.sessionId()));
    values.addValue(new TextValue(TOOL_PREFIX_KEY, defaults.toolPrefix()));
    values.addValue(new SecretValue(TOKEN_KEY, ""));

    values.setValidator(
        (map, statusListener) -> {
          try {
            parseMcpValues(map);
            return true;
          } catch (IllegalArgumentException invalid) {
            if (statusListener != null) {
              statusListener.setStatusText(invalid.getMessage(), MessageType.ERROR);
            }
            return false;
          }
        });

    return new ValuesMapDialog(
        "Ghidra Bridge - MCP Configuration",
        "Configure the MCP Streamable HTTP server for "
            + programLabel
            + ". Use distinct port and tool_prefix values when serving multiple Ghidra tabs.",
        values);
  }

  static WebSocketDefaults computeWebSocketDefaults(Program program) {
    int freePort =
        findFreePort(
            DEFAULT_HOST,
            DEFAULT_WS_PORT,
            Set.of(DEFAULT_MCP_PORT),
            port -> isPortAvailable(DEFAULT_HOST, port));
    String sessionId = defaultGuiSessionId(program, ACTIVE_SESSION_IDS);
    return new WebSocketDefaults(DEFAULT_HOST, freePort, DEFAULT_WS_PATH, sessionId);
  }

  static McpDefaults computeMcpDefaults(Program program) {
    int freePort =
        findFreePort(
            DEFAULT_HOST,
            DEFAULT_MCP_PORT,
            Set.of(),
            port -> isPortAvailable(DEFAULT_HOST, port));
    String sessionId = defaultGuiSessionId(program, ACTIVE_SESSION_IDS);
    String toolPrefix = defaultGuiToolPrefix(program, freePort, ACTIVE_MCP_TOOL_PREFIXES);
    return new McpDefaults(DEFAULT_HOST, freePort, DEFAULT_MCP_PATH, sessionId, toolPrefix);
  }

  static int findFreePort(
      String host, int preferredPort, Set<Integer> avoidPorts, IntPredicate portAvailability) {
    if (portAvailability.test(preferredPort)) {
      return preferredPort;
    }
    for (int candidate = preferredPort + 1; candidate <= MAX_PORT; candidate++) {
      if (avoidPorts.contains(candidate)) {
        continue;
      }
      if (portAvailability.test(candidate)) {
        return candidate;
      }
    }
    try (ServerSocket ephemeral = new ServerSocket(0, 1, InetAddress.getByName(host))) {
      return ephemeral.getLocalPort();
    } catch (IOException fallbackFailure) {
      return preferredPort;
    }
  }

  static boolean isPortAvailable(String host, int port) {
    try (ServerSocket socket = new ServerSocket()) {
      socket.bind(new InetSocketAddress(host, port));
      return true;
    } catch (IOException | IllegalArgumentException unavailable) {
      return false;
    }
  }

  static String defaultGuiSessionId(Program program, Set<String> activeSessionIds) {
    String base = Bootstrap.defaultSessionId(program);
    if (!activeSessionIds.contains(base)) {
      return base;
    }
    int suffix = 2;
    while (activeSessionIds.contains(base + "-" + suffix)) {
      suffix++;
    }
    return base + "-" + suffix;
  }

  static String defaultGuiToolPrefix(
      Program program, int selectedPort, Set<String> activeToolPrefixes) {
    if (selectedPort == DEFAULT_MCP_PORT
        && !activeToolPrefixes.contains(McpConfig.DEFAULT_TOOL_PREFIX)) {
      return McpConfig.DEFAULT_TOOL_PREFIX;
    }
    String rawName = program == null ? null : program.getName();
    String candidate = sanitizeToolPrefix(rawName);
    if (candidate == null
        || McpConfig.DEFAULT_TOOL_PREFIX.equals(candidate)
        || activeToolPrefixes.contains(candidate)) {
      String base =
          candidate == null || McpConfig.DEFAULT_TOOL_PREFIX.equals(candidate)
              ? McpConfig.DEFAULT_TOOL_PREFIX
              : candidate;
      candidate = appendPrefixSuffix(base, "_" + selectedPort);
    }
    int counter = 2;
    while (activeToolPrefixes.contains(candidate)) {
      candidate = appendPrefixSuffix(McpConfig.DEFAULT_TOOL_PREFIX, "_" + selectedPort + "_" + counter);
      counter++;
    }
    return McpConfig.requireToolPrefix(candidate);
  }

  static String sanitizeToolPrefix(String rawName) {
    if (rawName == null || rawName.isBlank()) {
      return null;
    }
    StringBuilder cleaned = new StringBuilder();
    boolean previousUnderscore = false;
    for (int i = 0; i < rawName.length(); i++) {
      char ch = rawName.charAt(i);
      if ((ch >= 'A' && ch <= 'Z')
          || (ch >= 'a' && ch <= 'z')
          || (ch >= '0' && ch <= '9')
          || ch == '-') {
        cleaned.append(ch);
        previousUnderscore = false;
      } else if (!previousUnderscore && !cleaned.isEmpty()) {
        cleaned.append('_');
        previousUnderscore = true;
      }
    }
    int end = cleaned.length();
    while (end > 0 && (cleaned.charAt(end - 1) == '_' || cleaned.charAt(end - 1) == '-')) {
      end--;
    }
    if (end == 0) {
      return null;
    }
    String token = cleaned.substring(0, end);
    char first = token.charAt(0);
    if (!((first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z'))) {
      token = "ghidra_" + token;
    }
    if (token.length() > MAX_TOOL_PREFIX_LENGTH) {
      token = token.substring(0, MAX_TOOL_PREFIX_LENGTH);
    }
    return token;
  }

  private static String appendPrefixSuffix(String base, String suffix) {
    int maxBaseLength = Math.max(1, MAX_TOOL_PREFIX_LENGTH - suffix.length());
    String trimmedBase = base.length() > maxBaseLength ? base.substring(0, maxBaseLength) : base;
    return trimmedBase + suffix;
  }

  static AgentConfig parseWebSocketValues(GValuesMap values, WebSocketDefaults defaults) {
    Objects.requireNonNull(values, "values");
    Objects.requireNonNull(defaults, "defaults");

    String wsUrl = AgentConfig.optionalText(values.getString(WS_URL_KEY));
    String host = AgentConfig.optionalText(values.getString(HOST_KEY));
    String port = AgentConfig.optionalText(values.getString(PORT_KEY));
    String path = AgentConfig.optionalText(values.getString(PATH_KEY));
    String sessionId = AgentConfig.optionalText(values.getString(SESSION_ID_KEY));
    String token = AgentConfig.optionalText(values.getString(TOKEN_KEY));
    String exitDeadline = AgentConfig.optionalText(values.getString(EXIT_DEADLINE_KEY));

    Map<String, String> map = new LinkedHashMap<>();
    if (wsUrl != null) {
      AgentConfig.parseWsUri(wsUrl);
      map.put(WS_URL_KEY, wsUrl);
      if (isExplicitlyOverridden(values, HOST_KEY, host, defaults.host())) {
        map.put(HOST_KEY, host);
      }
      if (isExplicitlyOverridden(values, PORT_KEY, port, Integer.toString(defaults.port()))) {
        map.put(PORT_KEY, port);
      }
      if (isExplicitlyOverridden(values, PATH_KEY, path, defaults.path())) {
        map.put(PATH_KEY, path);
      }
    } else {
      putIfPresent(map, HOST_KEY, host);
      putIfPresent(map, PORT_KEY, port);
      putIfPresent(map, PATH_KEY, path);
    }
    putIfPresent(map, SESSION_ID_KEY, sessionId);
    putIfPresent(map, TOKEN_KEY, token);
    putIfPresent(map, EXIT_DEADLINE_KEY, exitDeadline);
    return AgentConfig.fromMap(map);
  }

  static McpConfig parseMcpValues(GValuesMap values) {
    Objects.requireNonNull(values, "values");
    Map<String, String> map = new LinkedHashMap<>();
    putIfPresent(map, HOST_KEY, AgentConfig.optionalText(values.getString(HOST_KEY)));
    putIfPresent(map, PORT_KEY, AgentConfig.optionalText(values.getString(PORT_KEY)));
    putIfPresent(map, PATH_KEY, AgentConfig.optionalText(values.getString(PATH_KEY)));
    putIfPresent(map, SESSION_ID_KEY, AgentConfig.optionalText(values.getString(SESSION_ID_KEY)));
    putIfPresent(
        map, TOOL_PREFIX_KEY, AgentConfig.optionalText(values.getString(TOOL_PREFIX_KEY)));
    putIfPresent(map, TOKEN_KEY, AgentConfig.optionalText(values.getString(TOKEN_KEY)));
    return McpConfig.fromMap(map);
  }

  private static boolean isExplicitlyOverridden(
      GValuesMap values, String key, String currentValue, String defaultValue) {
    if (currentValue == null || currentValue.equals(defaultValue)) {
      return false;
    }
    AbstractValue<?> abstractValue = values.getAbstractValue(key);
    if (abstractValue instanceof TextValue textValue && !textValue.isFieldEnabled()) {
      return false;
    }
    return true;
  }

  private static void putIfPresent(Map<String, String> target, String key, String value) {
    if (value != null) {
      target.put(key, value);
    }
  }

  private static void bindOutboundModeFieldState(
      TextValue wsUrlValue, TextValue hostValue, TextValue portValue, TextValue pathValue) {
    JTextField wsUrlField = (JTextField) wsUrlValue.getComponent();
    Runnable syncState =
        () -> {
          boolean serverMode =
              wsUrlField.getText() == null || wsUrlField.getText().trim().isEmpty();
          hostValue.getComponent().setEnabled(serverMode);
          portValue.getComponent().setEnabled(serverMode);
          pathValue.getComponent().setEnabled(serverMode);
        };
    wsUrlField
        .getDocument()
        .addDocumentListener(
            new DocumentListener() {
              @Override
              public void insertUpdate(DocumentEvent event) {
                syncState.run();
              }

              @Override
              public void removeUpdate(DocumentEvent event) {
                syncState.run();
              }

              @Override
              public void changedUpdate(DocumentEvent event) {
                syncState.run();
              }
            });
    syncState.run();
  }

  private static String displayProgramName(Program program) {
    if (program == null) {
      return "current program";
    }
    String name = program.getName();
    return name == null || name.isBlank() ? "current program" : "'" + name.trim() + "'";
  }

  private static boolean showDockingDialog(String ignoredKind, ValuesMapDialog dialog) {
    DockingWindowManager.showDialog(dialog);
    return !dialog.isCancelled();
  }

  static final class SessionLease implements AutoCloseable {
    private final String sessionId;
    private final String mcpToolPrefix;
    private final AtomicBoolean closed = new AtomicBoolean(false);

    SessionLease(String sessionId, String mcpToolPrefix) {
      this.sessionId = sessionId;
      this.mcpToolPrefix = mcpToolPrefix;
    }

    @Override
    public void close() {
      if (!closed.compareAndSet(false, true)) {
        return;
      }
      if (sessionId != null) {
        ACTIVE_SESSION_IDS.remove(sessionId);
      }
      if (mcpToolPrefix != null) {
        ACTIVE_MCP_TOOL_PREFIXES.remove(mcpToolPrefix);
      }
    }
  }

  static final class TextValue extends StringValue {
    private JTextField textField;

    TextValue(String name, String defaultValue) {
      super(name, defaultValue);
    }

    @Override
    public JComponent getComponent() {
      if (textField == null) {
        textField = new JTextField(FIELD_COLUMNS);
        textField.setName(getName());
      }
      return textField;
    }

    boolean isFieldEnabled() {
      return textField == null || textField.isEnabled();
    }

    @Override
    protected void updateValueFromComponent() {
      if (textField != null) {
        setValue(textField.getText());
      }
    }

    @Override
    protected void updateComponentFromValue() {
      if (textField != null) {
        String value = getValue();
        textField.setText(value == null ? "" : value);
      }
    }

    @Override
    public String fromString(String valueString) {
      return valueString;
    }
  }

  static final class SecretValue extends StringValue {
    private JPasswordField passwordField;

    SecretValue(String name, String defaultValue) {
      super(name, defaultValue);
    }

    @Override
    public JComponent getComponent() {
      if (passwordField == null) {
        passwordField = new JPasswordField(FIELD_COLUMNS);
        passwordField.setName(getName());
      }
      return passwordField;
    }

    @Override
    protected void updateValueFromComponent() {
      if (passwordField != null) {
        char[] chars = passwordField.getPassword();
        try {
          setValue(new String(chars));
        } finally {
          java.util.Arrays.fill(chars, '\0');
        }
      }
    }

    @Override
    protected void updateComponentFromValue() {
      if (passwordField != null) {
        String value = getValue();
        passwordField.setText(value == null ? "" : value);
      }
    }

    @Override
    public String fromString(String valueString) {
      return valueString;
    }

    @Override
    protected String toString(String value) {
      return value == null || value.isBlank() ? "" : "<redacted>";
    }
  }

  private static final class BridgeValuesMap extends GValuesMap {
    @Override
    protected <T> T getValue(String name, Class<T> valueType, String typeName) {
      AbstractValue<?> value = valuesMap.get(name);
      if (value == null) {
        throw new IllegalArgumentException("No value defined for " + name);
      }
      if (valueType.isAssignableFrom(value.getClass())) {
        return valueType.cast(value);
      }
      throw new IllegalArgumentException(
          "Wrong type! No " + typeName + " value defined for: " + name);
    }
  }
}
