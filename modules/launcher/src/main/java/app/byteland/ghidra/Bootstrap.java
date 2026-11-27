package app.byteland.ghidra;

import app.byteland.ghidra.adapter.ghidra.GhidraServiceFactory;
import app.byteland.ghidra.agent.AgentClient;
import app.byteland.ghidra.agent.AgentConfig;
import app.byteland.ghidra.agent.AgentDispatcher;
import app.byteland.ghidra.mcp.McpConfig;
import app.byteland.ghidra.mcp.McpHttpServer;
import app.byteland.ghidra.network.NetworkBinding;
import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.program.ProgramService;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraState;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import java.io.Console;
import java.net.BindException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.function.Function;

/**
 * The generated Bridge and GhidraMcp scripts call this entry point.
 * It starts the WebSocket or MCP transport.
 */
@SuppressWarnings("try")
public final class Bootstrap {
  static final int DEFAULT_WS_PORT = 8765;
  static final int MAX_GUI_PORT_ATTEMPTS = 64;
  private static final String LOOPBACK_HOST = "127.0.0.1";
  private static final String BRIDGE_PREFIX = "[ghidra-bridge]";
  private static final String MCP_PREFIX = "[ghidra-mcp]";
  private static final String SESSION_ID_ARGUMENT = "session_id";
  private static final String TOKEN_ARGUMENT = "token";
  private static final String TOOL_PREFIX_ARGUMENT = "tool_prefix";
  private static final int GENERATED_TOKEN_BYTES = 32;
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();
  private static final String BANNER_DIVIDER =
      "============================================================";

  private Bootstrap() {}

  public static void startFromScript(GhidraScript script, String[] args, Runnable onShutdown)
      throws Exception {
    startFromScript(script, args, onShutdown, GhidraServiceFactory::create, DEFAULT_WS_PORT);
  }

  static void startFromScript(
      GhidraScript script,
      String[] args,
      Runnable onShutdown,
      Function<GhidraScript, BridgeServices> serviceFactory,
      int defaultPort)
      throws Exception {
    startFromScript(
        script,
        args,
        onShutdown,
        serviceFactory,
        defaultPort,
        script == null ? null : findConsoleService(script));
  }

  static void startFromScript(
      GhidraScript script,
      String[] args,
      Runnable onShutdown,
      Function<GhidraScript, BridgeServices> serviceFactory,
      int defaultPort,
      ConsoleService guiConsole)
      throws Exception {
    Program program = requireScriptProgram(script);
    boolean headless = script.isRunningHeadless();
    Console systemConsole = System.console();
    boolean interactiveConsoleAvailable = guiConsole != null || systemConsole != null;
    Map<String, String> rawArgs = parseArgsOrPrintUsage(script, args, Bootstrap::printUsage);
    EffectiveConfig initialConfig;
    try {
      initialConfig =
          resolveWsConfig(rawArgs, program, defaultPort, false, interactiveConsoleAvailable, null);
    } catch (IllegalArgumentException error) {
      printUsage(script);
      throw error;
    }

    boolean autoPortFallback =
        !headless
            && NetworkBinding.optionalText(rawArgs.get("ws_url")) == null
            && isAutoPortFallback(rawArgs);
    BooleanSupplier cancelRequested = scriptCancelRequested(script);

    BridgeServices services = serviceFactory.apply(script);
    if (initialConfig.config().isOutboundMode()) {
      runOutboundSession(
          script, program, initialConfig, services, onShutdown, cancelRequested, headless);
      return;
    }

    runEmbeddedWsSession(
        script,
        program,
        rawArgs,
        initialConfig,
        services,
        onShutdown,
        cancelRequested,
        headless,
        autoPortFallback,
        defaultPort,
        guiConsole,
        systemConsole,
        interactiveConsoleAvailable);
  }

  public static void startMcpFromScript(GhidraScript script, String[] args, Runnable onShutdown)
      throws Exception {
    startMcpFromScript(
        script, args, onShutdown, GhidraServiceFactory::create, McpConfig.DEFAULT_PORT);
  }

  static void startMcpFromScript(
      GhidraScript script,
      String[] args,
      Runnable onShutdown,
      Function<GhidraScript, BridgeServices> serviceFactory,
      int defaultPort)
      throws Exception {
    Program program = requireScriptProgram(script);
    boolean headless = script.isRunningHeadless();
    Map<String, String> rawArgs = parseArgsOrPrintUsage(script, args, Bootstrap::printMcpUsage);
    McpConfig initialConfig;
    try {
      initialConfig = resolveMcpConfig(rawArgs, program, defaultPort, false);
    } catch (IllegalArgumentException error) {
      printMcpUsage(script);
      throw error;
    }

    boolean autoPortFallback = !headless && isAutoPortFallback(rawArgs);
    int maxAttempts = autoPortFallback ? MAX_GUI_PORT_ATTEMPTS : 1;

    BridgeServices services = serviceFactory.apply(script);
    McpConfig boundConfig = null;
    AgentDispatcher boundDispatcher = null;
    McpHttpServer boundServer = null;
    boolean usedFallback = false;

    try {
      for (int offset = 0; offset < maxAttempts; offset++) {
        int candidatePort = defaultPort + offset;
        McpConfig candidateConfig =
            offset == 0
                ? initialConfig
                : resolveMcpConfig(rawArgs, program, candidatePort, true);
        AgentDispatcher dispatcher = new AgentDispatcher(services, candidateConfig.sessionId());
        McpHttpServer server = null;
        try {
          server = new McpHttpServer(candidateConfig, dispatcher, script::println);
          boundConfig = candidateConfig;
          boundDispatcher = dispatcher;
          boundServer = server;
          usedFallback = offset > 0;
          break;
        } catch (BindException bindFailure) {
          if (server != null) {
            server.close();
          }
          boolean canRetry = offset + 1 < maxAttempts && candidatePort < 65535;
          if (!canRetry) {
            throw bindFailure;
          }
        } catch (Exception | Error failure) {
          if (server != null) {
            server.close();
          }
          throw failure;
        }
      }

      script.println("[ghidra-mcp] Starting MCP HTTP service");
      if (usedFallback) {
        script.println(
            "[ghidra-mcp] Default port "
                + defaultPort
                + " is busy; bound fallback port "
                + boundConfig.port()
                + ".");
      }
      printMcpBanner(script, program, boundConfig);
      if (headless) {
        AgentDispatcher checkpointDispatcher = boundDispatcher;
        checkpointDispatcher.runExclusive(() -> saveCheckpoint(script, program, MCP_PREFIX));
      }
      boundServer.start();
      script.println("[ghidra-mcp] MCP endpoint is listening for HTTP clients.");
    } catch (Exception | Error startupFailure) {
      try {
        if (boundServer != null) {
          boundServer.close();
        }
      } finally {
        if (boundDispatcher != null) {
          boundDispatcher.close();
        } else {
          services.close();
        }
      }
      throw startupFailure;
    }

    try (GracefulExit gracefulExit =
            gracefulExit(services.programService(), program, script, MCP_PREFIX, headless);
        AgentDispatcher activeDispatcher = boundDispatcher;
        McpHttpServer activeServer = boundServer) {
      if (onShutdown != null) {
        gracefulExit.installShutdownHook(activeServer::close, onShutdown);
      }

      boolean stoppedBySession = false;
      boolean interrupted = false;
      try {
        stoppedBySession = activeServer.awaitShutdown(scriptCancelRequested(script));
      } catch (InterruptedException interruptedException) {
        interrupted = true;
        script.println("[ghidra-mcp] Stop requested; shutting down MCP HTTP service.");
      }
      if (!stoppedBySession && !interrupted) {
        script.println("[ghidra-mcp] Stop requested; shutting down MCP HTTP service.");
      }
      script.println("[ghidra-mcp] MCP session ended.");
      if (interrupted) {
        Thread.currentThread().interrupt();
      }
    }
  }

  private static Program requireScriptProgram(GhidraScript script) {
    if (script == null) {
      throw new IllegalArgumentException("script is required");
    }
    Program program = script.getCurrentProgram();
    if (program == null) {
      throw new IllegalStateException("No current program is open in Ghidra");
    }
    return program;
  }

  private static Map<String, String> parseArgsOrPrintUsage(
      GhidraScript script, String[] args, Consumer<GhidraScript> usagePrinter) {
    try {
      return NetworkBinding.parseArgs(args);
    } catch (IllegalArgumentException error) {
      usagePrinter.accept(script);
      throw error;
    }
  }

  private static void runOutboundSession(
      GhidraScript script,
      Program program,
      EffectiveConfig effectiveConfig,
      BridgeServices services,
      Runnable onShutdown,
      BooleanSupplier cancelRequested,
      boolean headless)
      throws Exception {
    AgentConfig config = effectiveConfig.config();
    script.println("[ghidra-bridge] Starting bridge service");
    script.println("[ghidra-bridge]   Program: " + program.getName());
    for (String defaultMessage : effectiveConfig.defaultMessages()) {
      script.println("[ghidra-bridge]   Default: " + defaultMessage);
    }
    script.println("[ghidra-bridge]   Mode: outbound WebSocket client");
    script.println("[ghidra-bridge]   WebSocket URL: " + config.redactedWsUrl());
    script.println(
        "[ghidra-bridge]   Auth Token: " + (config.token() == null ? "disabled" : "configured"));
    script.println("[ghidra-bridge]   Session ID: " + config.sessionId());
    script.println("[ghidra-bridge] Connecting to remote bridge...");

    AgentDispatcher dispatcher = new AgentDispatcher(services, config.sessionId());
    AgentClient client =
        new AgentClient(
            config,
            dispatcher,
            new AgentClient.LifecycleListener() {
              @Override
              public void onConnected() {
                script.println("[ghidra-bridge] Outbound bridge connected to remote endpoint.");
              }
            });

    AgentClient.ActiveSession session;
    try {
      session = client.openSession(cancelRequested);
    } catch (Exception | Error connectFailure) {
      services.close();
      throw connectFailure;
    }

    if (session == null) {
      dispatcher.close();
      script.println("[ghidra-bridge] Bridge session ended.");
      return;
    }

    printOutboundWsBanner(script, program, config);
    if (headless) {
      dispatcher.runExclusive(() -> saveCheckpoint(script, program, BRIDGE_PREFIX));
    }

    try (GracefulExit gracefulExit =
            gracefulExit(services.programService(), program, script, BRIDGE_PREFIX, headless);
        AgentDispatcher activeDispatcher = dispatcher;
        AgentClient.ActiveSession activeSession = session) {
      if (onShutdown != null) {
        gracefulExit.installShutdownHook(client::disconnect, onShutdown);
      }

      try {
        activeSession.awaitDisconnect();
      } finally {
        // Start the deadline for all session end conditions.
        // The close, the save, and the exit follow.
        if (config.exitDeadlineSeconds() != null) {
          gracefulExit.startExitDeadline(
              Duration.ofSeconds(config.exitDeadlineSeconds()), script::printerr);
        }
      }
      script.println("[ghidra-bridge] Bridge session ended.");
    }
  }

  private static void runEmbeddedWsSession(
      GhidraScript script,
      Program program,
      Map<String, String> rawArgs,
      EffectiveConfig initialConfig,
      BridgeServices services,
      Runnable onShutdown,
      BooleanSupplier cancelRequested,
      boolean headless,
      boolean autoPortFallback,
      int defaultPort,
      ConsoleService guiConsole,
      Console systemConsole,
      boolean interactiveConsoleAvailable)
      throws Exception {
    int maxAttempts = autoPortFallback ? MAX_GUI_PORT_ATTEMPTS : 1;
    EffectiveConfig boundEffective = null;
    AgentDispatcher boundDispatcher = null;
    AgentClient boundClient = null;
    AgentClient.ActiveSession boundSession = null;
    boolean usedFallback = false;

    try {
      for (int offset = 0; offset < maxAttempts; offset++) {
        int candidatePort = defaultPort + offset;
        EffectiveConfig candidate =
            offset == 0
                ? initialConfig
                : resolveWsConfig(
                    rawArgs,
                    program,
                    candidatePort,
                    true,
                    interactiveConsoleAvailable,
                    initialConfig.generatedToken());
        AgentDispatcher dispatcher = new AgentDispatcher(services, candidate.config().sessionId());
        AgentClient client = new AgentClient(candidate.config(), dispatcher);
        try {
          AgentClient.ActiveSession session = client.openSession(cancelRequested);
          boundEffective = candidate;
          boundDispatcher = dispatcher;
          boundClient = client;
          boundSession = session;
          usedFallback = offset > 0;
          break;
        } catch (BindException bindFailure) {
          boolean canRetry = offset + 1 < maxAttempts && candidatePort < 65535;
          if (!canRetry) {
            throw bindFailure;
          }
        }
      }
    } catch (Exception | Error startupFailure) {
      services.close();
      throw startupFailure;
    }

    AgentConfig config = boundEffective.config();
    script.println("[ghidra-bridge] Starting bridge service");
    for (String defaultMessage : boundEffective.defaultMessages()) {
      script.println("[ghidra-bridge]   Default: " + defaultMessage);
    }
    if (usedFallback) {
      script.println(
          "[ghidra-bridge] Default port "
              + defaultPort
              + " is busy; bound fallback port "
              + config.port()
              + ".");
    }
    printEmbeddedWsBanner(
        script, program, config, guiConsole, systemConsole, boundEffective.generatedToken());
    if (headless) {
      AgentDispatcher checkpointDispatcher = boundDispatcher;
      checkpointDispatcher.runExclusive(() -> saveCheckpoint(script, program, BRIDGE_PREFIX));
    }
    script.println("[ghidra-bridge] Embedded bridge is listening for WebSocket clients.");

    try (GracefulExit gracefulExit =
            gracefulExit(services.programService(), program, script, BRIDGE_PREFIX, headless);
        AgentDispatcher activeDispatcher = boundDispatcher;
        AgentClient.ActiveSession activeSession = boundSession) {
      if (onShutdown != null) {
        gracefulExit.installShutdownHook(boundClient::disconnect, onShutdown);
      }

      activeSession.awaitDisconnect();
      script.println("[ghidra-bridge] Bridge session ended.");
    }
  }

  private static void printOutboundWsBanner(
      GhidraScript script, Program program, AgentConfig config) {
    script.println("[ghidra-bridge] " + BANNER_DIVIDER);
    script.println("[ghidra-bridge] WebSocket endpoint ready");
    script.println("[ghidra-bridge]   Program: " + program.getName());
    script.println("[ghidra-bridge]   Endpoint URL: " + config.redactedWsUrl());
    script.println("[ghidra-bridge]   session_id: " + config.sessionId());
    script.println("[ghidra-bridge]   tool_prefix: none (WebSocket JSON-RPC)");
    script.println(
        "[ghidra-bridge]   Auth Token: " + (config.token() == null ? "disabled" : "configured"));
    script.println("[ghidra-bridge] " + BANNER_DIVIDER);
  }

  private static void printEmbeddedWsBanner(
      GhidraScript script,
      Program program,
      AgentConfig config,
      ConsoleService guiConsole,
      Console systemConsole,
      String generatedToken) {
    script.println("[ghidra-bridge] " + BANNER_DIVIDER);
    script.println("[ghidra-bridge] WebSocket endpoint ready");
    script.println("[ghidra-bridge]   Program: " + program.getName());
    script.println("[ghidra-bridge]   Endpoint URL: " + config.serverEndpoint());
    script.println("[ghidra-bridge]   session_id: " + config.sessionId());
    script.println("[ghidra-bridge]   tool_prefix: none (WebSocket JSON-RPC)");
    reportServerAuthToken(script, guiConsole, systemConsole, generatedToken);
    script.println("[ghidra-bridge] " + BANNER_DIVIDER);
  }

  private static void printMcpBanner(GhidraScript script, Program program, McpConfig mcpConfig) {
    script.println("[ghidra-mcp] " + BANNER_DIVIDER);
    script.println("[ghidra-mcp] MCP HTTP endpoint ready");
    script.println("[ghidra-mcp]   Program: " + program.getName());
    script.println("[ghidra-mcp]   Endpoint URL: " + mcpConfig.endpoint());
    script.println("[ghidra-mcp]   session_id: " + mcpConfig.sessionId());
    script.println("[ghidra-mcp]   tool_prefix: " + mcpConfig.toolPrefix());
    script.println(
        "[ghidra-mcp]   Auth Token: " + (mcpConfig.token() == null ? "disabled" : "configured"));
    script.println(
        "[ghidra-mcp]   Allowed Origins: " + formatAllowedOrigins(mcpConfig.allowedOrigins()));
    script.println("[ghidra-mcp] " + BANNER_DIVIDER);
  }

  private static GracefulExit gracefulExit(
      ProgramService programService,
      Program program,
      GhidraScript script,
      String prefix,
      boolean headless) {
    if (!headless) {
      return GracefulExit.disabled();
    }
    return new GracefulExit(
        () -> {
          if (!program.isChanged()) {
            return false;
          }
          programService.saveProgram();
          return true;
        },
        () -> script.println(prefix + " Program save on exit completed."),
        failure ->
            script.printerr(prefix + " Program save on exit failed: " + errorMessage(failure)));
  }

  private static void saveCheckpoint(GhidraScript script, Program program, String prefix) {
    if (!program.isChanged()) {
      return;
    }
    try {
      script.saveProgram(program);
      script.println(prefix + " Program save checkpoint completed.");
    } catch (Exception failure) {
      script.println(prefix + " Program save checkpoint skipped: " + failure.getMessage());
    }
  }

  private static String errorMessage(Throwable failure) {
    String message = failure.getMessage();
    return message == null || message.isBlank() ? failure.getClass().getName() : message;
  }

  private static BooleanSupplier scriptCancelRequested(GhidraScript script) {
    return () -> script.getMonitor() != null && script.getMonitor().isCancelled();
  }

  private static void printUsage(GhidraScript script) {
    script.printerr("[ghidra-bridge] Invalid startup arguments.");
    script.printerr(
        "[ghidra-bridge] Defaults are used when ws_url, port, token, and session_id are omitted"
            + " in an interactive console.");
    script.printerr(
        "[ghidra-bridge] Non-interactive headless server mode requires token=<secret>.");
    script.printerr(
        "[ghidra-bridge] If you configure transport manually, use ws_url or host/port/path.");
    script.printerr(
        "[ghidra-bridge] Example (embedded): port=8765 host="
            + LOOPBACK_HOST
            + " path=/ws/agent"
            + " session_id=demo-session token=secret");
    script.printerr(
        "[ghidra-bridge] Example (outbound): ws_url=ws://"
            + LOOPBACK_HOST
            + ":8765/ws/agent"
            + " session_id=demo-session token=secret");
  }

  private static void printMcpUsage(GhidraScript script) {
    script.printerr("[ghidra-mcp] Invalid startup arguments.");
    script.printerr(
        "[ghidra-mcp] Defaults: host="
            + LOOPBACK_HOST
            + " port=8766 path=/mcp"
            + " session_id=<current-program-name> tool_prefix=ghidra"
            + " allowed_origins=<loopback-and-host>");
    script.printerr(
        "[ghidra-mcp] Example: host="
            + LOOPBACK_HOST
            + " port=8766 path=/mcp session_id=demo-session"
            + " token=secret allowed_origins=https://inspector.example.com");
  }

  private static String formatAllowedOrigins(Set<String> allowedOrigins) {
    if (allowedOrigins == null) {
      return "loopback and host (default)";
    }
    if (allowedOrigins.isEmpty()) {
      return "none";
    }
    return String.join(", ", allowedOrigins);
  }

  static EffectiveConfig resolveConfig(String[] args, Program program) {
    return resolveConfig(args, program, true);
  }

  static EffectiveConfig resolveConfig(
      String[] args, Program program, boolean interactiveConsoleAvailable) {
    return resolveWsConfig(
        NetworkBinding.parseArgs(args),
        program,
        DEFAULT_WS_PORT,
        false,
        interactiveConsoleAvailable,
        null);
  }

  static EffectiveConfig resolveWsConfig(
      Map<String, String> rawArgs,
      Program program,
      int candidatePort,
      boolean fallback,
      boolean interactiveConsoleAvailable,
      String reusableGeneratedToken) {
    Map<String, String> parsedArgs = new LinkedHashMap<>(rawArgs);
    List<String> defaultMessages = new ArrayList<>();

    if (NetworkBinding.optionalText(parsedArgs.get("ws_url")) == null
        && NetworkBinding.optionalText(parsedArgs.get("port")) == null) {
      if (NetworkBinding.optionalText(parsedArgs.get("host")) == null) {
        parsedArgs.put("host", LOOPBACK_HOST);
        defaultMessages.add("host=" + LOOPBACK_HOST);
      }
      String portText = Integer.toString(candidatePort);
      parsedArgs.put("port", portText);
      defaultMessages.add("port=" + portText + " (embedded server mode)");
    }

    String defaultSessionId = applyDefaultSessionId(parsedArgs, program, candidatePort, fallback);
    if (defaultSessionId != null) {
      defaultMessages.add("session_id=" + defaultSessionId);
    }

    String generatedToken = null;
    if (NetworkBinding.optionalText(parsedArgs.get("ws_url")) == null
        && !parsedArgs.containsKey(TOKEN_ARGUMENT)) {
      if (!interactiveConsoleAvailable) {
        throw new IllegalArgumentException(
            "token is required in headless server mode when no interactive console is available;"
                + " pass token=<secret>");
      }
      generatedToken =
          reusableGeneratedToken != null ? reusableGeneratedToken : generateSessionToken();
      parsedArgs.put(TOKEN_ARGUMENT, generatedToken);
      defaultMessages.add("token=<generated>");
    }

    return new EffectiveConfig(AgentConfig.fromMap(parsedArgs), defaultMessages, generatedToken);
  }

  static String generateSessionToken() {
    byte[] bytes = new byte[GENERATED_TOKEN_BYTES];
    SECURE_RANDOM.nextBytes(bytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  static boolean reportServerAuthToken(GhidraScript script, String generatedToken) {
    return reportServerAuthToken(script, findConsoleService(script), System.console(), generatedToken);
  }

  static boolean reportServerAuthToken(
      GhidraScript script,
      ConsoleService guiConsole,
      Console systemConsole,
      String generatedToken) {
    if (generatedToken == null) {
      script.println("[ghidra-bridge]   Auth Token: configured");
      return true;
    }
    if (guiConsole != null) {
      script.println("[ghidra-bridge]   Auth Token: generated (printed to console)");
      guiConsole.println("[ghidra-bridge]   Session Token: " + generatedToken);
      return true;
    }
    if (systemConsole != null) {
      script.println("[ghidra-bridge]   Auth Token: generated (printed to console)");
      systemConsole.writer().println("[ghidra-bridge]   Session Token: " + generatedToken);
      systemConsole.flush();
      return true;
    }
    script.println(
        "[ghidra-bridge]   Auth Token: generated (no interactive console; pass token=<secret> in"
            + " headless mode)");
    return false;
  }

  private static ConsoleService findConsoleService(GhidraScript script) {
    final GhidraState state;
    try {
      state = script.getState();
    } catch (NullPointerException uninitializedState) {
      return null;
    }
    if (state == null) {
      return null;
    }
    PluginTool tool = state.getTool();
    return tool == null ? null : tool.getService(ConsoleService.class);
  }

  static McpConfig resolveMcpConfig(
      Map<String, String> rawArgs, Program program, int candidatePort, boolean fallback) {
    Map<String, String> parsedArgs = new LinkedHashMap<>(rawArgs);
    if (NetworkBinding.optionalText(parsedArgs.get("host")) == null) {
      parsedArgs.put("host", LOOPBACK_HOST);
    }
    if (NetworkBinding.optionalText(parsedArgs.get("port")) == null) {
      parsedArgs.put("port", Integer.toString(candidatePort));
    }
    applyDefaultSessionId(parsedArgs, program, candidatePort, fallback);
    if (fallback && NetworkBinding.optionalText(parsedArgs.get(TOOL_PREFIX_ARGUMENT)) == null) {
      parsedArgs.put(
          TOOL_PREFIX_ARGUMENT,
          McpConfig.deriveFallbackToolPrefix(programNameOrNull(program), candidatePort));
    }
    return McpConfig.fromMap(parsedArgs);
  }

  static McpConfig resolveMcpConfig(String[] args, Program program) {
    return resolveMcpConfig(
        NetworkBinding.parseArgs(args), program, McpConfig.DEFAULT_PORT, false);
  }

  private static String applyDefaultSessionId(
      Map<String, String> parsedArgs, Program program, int candidatePort, boolean fallback) {
    if (NetworkBinding.optionalText(parsedArgs.get(SESSION_ID_ARGUMENT)) != null) {
      return null;
    }
    String programName = programNameOrNull(program);
    String sessionId =
        fallback
            ? McpConfig.deriveFallbackSessionId(programName, candidatePort)
            : NetworkBinding.defaultSessionId(programName);
    parsedArgs.put(SESSION_ID_ARGUMENT, sessionId);
    return sessionId;
  }

  private static String programNameOrNull(Program program) {
    return program == null ? null : program.getName();
  }

  private static boolean isAutoPortFallback(Map<String, String> rawArgs) {
    return NetworkBinding.optionalText(rawArgs.get("port")) == null
        && isDefaultLoopbackHost(rawArgs.get("host"));
  }

  private static boolean isDefaultLoopbackHost(String host) {
    String normalized = NetworkBinding.optionalText(host);
    return normalized == null || LOOPBACK_HOST.equals(normalized);
  }

  record EffectiveConfig(
      AgentConfig config, List<String> defaultMessages, String generatedToken) {
    EffectiveConfig {
      defaultMessages = List.copyOf(defaultMessages);
    }
  }
}
