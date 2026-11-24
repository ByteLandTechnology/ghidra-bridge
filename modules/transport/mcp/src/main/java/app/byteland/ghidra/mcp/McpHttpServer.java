package app.byteland.ghidra.mcp;

import app.byteland.ghidra.ExecutorShutdown;
import app.byteland.ghidra.JsonRpc;
import app.byteland.ghidra.JsonUtil;
import app.byteland.ghidra.agent.AgentDispatcher;
import app.byteland.ghidra.api.ApiCatalog.MethodDescriptor;
import app.byteland.ghidra.api.ApiFailures;
import app.byteland.ghidra.network.NetworkBinding;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.BindException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/**
 * HTTP server that exposes the bridge API as grouped MCP tools through Streamable HTTP and SSE.
 */
public final class McpHttpServer implements AutoCloseable {
  static final int MAX_REQUEST_BODY_BYTES = 16 * 1024 * 1024;
  private static final int HTTP_PAYLOAD_TOO_LARGE = 413;
  private static final int JSONRPC_PARSE_ERROR = -32700;
  private static final int JSONRPC_INVALID_REQUEST = -32600;
  private static final int JSONRPC_METHOD_NOT_FOUND = -32601;
  private static final int JSONRPC_INVALID_PARAMS = -32602;
  private static final int JSONRPC_INTERNAL_ERROR = -32603;
  private static final int JSONRPC_UNAUTHORIZED = -32001;
  private static final int JSONRPC_RESOURCE_NOT_FOUND = -32002;
  private static final String MCP_PROTOCOL_VERSION = "2026-07-28";
  private static final String INITIALIZE_PROTOCOL_VERSION = "2025-11-25";
  private static final List<String> INITIALIZE_PROTOCOL_VERSIONS =
      List.of("2024-11-05", "2025-03-26", "2025-06-18", INITIALIZE_PROTOCOL_VERSION);
  private static final List<String> SUPPORTED_PROTOCOL_VERSIONS =
      List.of(MCP_PROTOCOL_VERSION, INITIALIZE_PROTOCOL_VERSION, "2025-06-18", "2025-03-26", "2024-11-05");
  private static final int HEADER_MISMATCH = -32020;
  private static final int UNSUPPORTED_PROTOCOL_VERSION = -32022;
  private static final String MCP_TOOLS_RESOURCE_URI = "ghidra-bridge://contracts/mcp-tools";
  private static final String HTTP_GET_METHOD = "GET";
  private static final String HTTP_OPTIONS_METHOD = "OPTIONS";
  private static final String HTTP_POST_METHOD = "POST";
  private static final String NAME_FIELD = "name";
  private static final String URI_FIELD = "uri";
  private static final String SESSION_ID_PARAM = "sessionId";
  private static final long DEFAULT_SSE_KEEPALIVE_MILLIS = TimeUnit.SECONDS.toMillis(15);

  private final McpConfig config;
  private final boolean loopbackListener;
  private final String normalizedConfiguredHost;
  private final InetAddress configuredHostLiteral;
  private final AgentDispatcher dispatcher;
  private final Consumer<String> requestLogSink;
  private final long sseKeepaliveMillis;
  private final McpToolRegistry toolRegistry;
  private final String toolContractJson;
  private final HttpServer server;
  private final ExecutorService executor;
  private final CountDownLatch shutdownLatch = new CountDownLatch(1);
  private final AtomicBoolean closed = new AtomicBoolean(false);
  private final ConcurrentHashMap<String, SseSession> sseSessions = new ConcurrentHashMap<>();

  public McpHttpServer(McpConfig config, AgentDispatcher dispatcher) throws IOException {
    this(config, dispatcher, McpHttpServer::discardRequestLog);
  }

  public McpHttpServer(
      McpConfig config, AgentDispatcher dispatcher, Consumer<String> requestLogSink)
      throws IOException {
    this(config, dispatcher, requestLogSink, DEFAULT_SSE_KEEPALIVE_MILLIS);
  }

  McpHttpServer(
      McpConfig config,
      AgentDispatcher dispatcher,
      Consumer<String> requestLogSink,
      long sseKeepaliveMillis)
      throws IOException {
    if (sseKeepaliveMillis <= 0L) {
      throw new IllegalArgumentException("sseKeepaliveMillis must be positive");
    }
    this.config = Objects.requireNonNull(config, "config");
    this.loopbackListener = NetworkBinding.isLoopback(config.host());
    this.normalizedConfiguredHost = normalizeHost(config.host());
    this.configuredHostLiteral = parseIpLiteral(this.normalizedConfiguredHost);
    this.dispatcher = Objects.requireNonNull(dispatcher, "dispatcher");
    this.requestLogSink = Objects.requireNonNull(requestLogSink, "requestLogSink");
    this.sseKeepaliveMillis = sseKeepaliveMillis;
    this.toolRegistry = new McpToolRegistry(dispatcher.methodCatalog(), config.toolPrefix());
    Map<String, Object> toolContract = new LinkedHashMap<>();
    toolContract.put("protocol_version", MCP_PROTOCOL_VERSION);
    toolContract.put("tools", toolRegistry.listTools());
    this.toolContractJson = JsonUtil.toJson(toolContract);
    this.server = createServer(config);
    this.executor = Executors.newVirtualThreadPerTaskExecutor();
    this.server.setExecutor(executor);
    this.server.createContext(config.path(), new JsonRpcHandler());
  }

  private static HttpServer createServer(McpConfig config) throws IOException {
    try {
      return HttpServer.create(new InetSocketAddress(config.host(), config.port()), 0);
    } catch (BindException error) {
      BindException friendly =
          new BindException(
              "MCP endpoint "
                  + config.endpoint()
                  + " is already in use. Stop the existing Bridge/GhidraMcp script, close the old"
                  + " Ghidra session, or pass a different port value.");
      friendly.addSuppressed(error);
      throw friendly;
    }
  }

  public void start() {
    server.start();
  }

  public void awaitShutdown() throws InterruptedException {
    shutdownLatch.await();
  }

  public boolean awaitShutdown(BooleanSupplier cancelRequested) throws InterruptedException {
    return awaitShutdown(shutdownLatch, cancelRequested, this::close, 250L);
  }

  public String endpoint() {
    return config.endpoint();
  }

  int activeSseSessionCount() {
    return sseSessions.size();
  }

  @Override
  public void close() {
    if (!closed.compareAndSet(false, true)) {
      return;
    }
    server.stop(0);
    for (SseSession session : sseSessions.values()) {
      session.close();
    }
    sseSessions.clear();
    ExecutorShutdown.shutdownAndAwait(executor);
    shutdownLatch.countDown();
  }

  static boolean awaitShutdown(
      CountDownLatch latch, BooleanSupplier cancelRequested, Runnable closeAction, long pollMillis)
      throws InterruptedException {
    Objects.requireNonNull(latch, "latch");
    Objects.requireNonNull(cancelRequested, "cancelRequested");
    Objects.requireNonNull(closeAction, "closeAction");
    try {
      while (true) {
        if (latch.await(pollMillis, TimeUnit.MILLISECONDS)) {
          return true;
        }
        if (cancelRequested.getAsBoolean()) {
          closeAction.run();
          return false;
        }
      }
    } catch (InterruptedException interrupted) {
      closeAction.run();
      throw interrupted;
    }
  }

  private final class JsonRpcHandler implements HttpHandler {
    @Override
    public void handle(HttpExchange exchange) throws IOException {
      RequestLog log = new RequestLog(requestLogSink);
      try (exchange) {
        try {
          NetworkBinding.HostValidationResult hostValidation = validateHost(exchange);
          if (!hostValidation.isValid()) {
            int status = hostValidation.httpStatus();
            log.method(exchange.getRequestMethod()).error().status(status);
            writePlain(exchange, status, hostValidation.message());
            return;
          }
          OriginValidation originValidation = validateOrigin(exchange);
          if (!originValidation.allowed()) {
            log.method(exchange.getRequestMethod()).error().status(403);
            writePlain(exchange, 403, "Forbidden origin");
            return;
          }
          addCommonHeaders(exchange, originValidation.origin());

          String requestMethod = exchange.getRequestMethod();
          if (HTTP_OPTIONS_METHOD.equalsIgnoreCase(requestMethod)) {
            log.method(HTTP_OPTIONS_METHOD).ok().status(204);
            sendNoBody(exchange, 204);
            return;
          }
          if ("HEAD".equalsIgnoreCase(requestMethod)) {
            log.method("HEAD").ok().status(200);
            sendNoBody(exchange, 200);
            return;
          }

          if (hasQueryToken(exchange.getRequestURI())) {
            log.error().status(400);
            writeJsonRpcError(
                exchange,
                400,
                null,
                JSONRPC_INVALID_REQUEST,
                "Query-string tokens are not supported");
            return;
          }

          if (!authorize(exchange)) {
            exchange.getResponseHeaders().set("WWW-Authenticate", "Bearer");
            log.error().status(401);
            writeJsonRpcError(exchange, 401, null, JSONRPC_UNAUTHORIZED, "Unauthorized");
            return;
          }

          if (HTTP_GET_METHOD.equalsIgnoreCase(requestMethod)) {
            handleSseGet(exchange, log);
            return;
          }

          if (!HTTP_POST_METHOD.equalsIgnoreCase(requestMethod)) {
            exchange.getResponseHeaders().set("Allow", "POST, GET, OPTIONS");
            log.method(requestMethod).error().status(405);
            writeJsonRpcError(
                exchange,
                405,
                null,
                JSONRPC_INVALID_REQUEST,
                "Only POST and GET (SSE) are supported for this MCP endpoint");
            return;
          }

          String sessionId = getQueryParameter(exchange.getRequestURI(), SESSION_ID_PARAM);
          SseSession sseSession = null;
          if (sessionId != null) {
            sseSession = sseSessions.get(sessionId);
            if (sseSession == null || !sseSession.isActive()) {
              log.error().status(404);
              writeJsonRpcError(
                  exchange, 404, null, JSONRPC_INVALID_REQUEST, "SSE session not found or expired");
              return;
            }
          }

          validateContentLength(exchange.getRequestHeaders());
          if (!String.valueOf(firstHeader(exchange, "Content-Type")).startsWith("application/json")) {
            throw new JsonRpcError(415, null, JSONRPC_INVALID_REQUEST, "Content-Type must be application/json");
          }
          Map<String, Object> request = parseRequest(readBody(exchange));
          validateJsonRpcEnvelope(request);
          boolean statelessProtocol = usesStatelessProtocol(exchange, request);
          if (statelessProtocol) {
            validateMetadata(exchange, request);
          } else {
            validateInitializeProtocol(exchange, request);
          }
          Object id = request.get("id");
          Object response = handleRequest(request, id, log, statelessProtocol);
          if (sseSession != null) {
            if (response != null) {
              sseSession.sendEvent("message", JsonUtil.toJson(response));
            }
            log.id(id).ok().status(202);
            exchange.sendResponseHeaders(202, -1);
            return;
          }
          if (response == null) {
            log.id(id).ok().status(202);
            exchange.sendResponseHeaders(202, -1);
            return;
          }
          writeJson(exchange, 200, response);
        } catch (JsonRpcError error) {
          log.error()
              .status(error.httpStatus())
              .id(error.id())
              .cause(error.httpStatus() >= 500 ? rootMessage(error) : null);
          if (error.httpStatus() == HTTP_PAYLOAD_TOO_LARGE) {
            exchange.getResponseHeaders().set("Connection", "close");
          }
          Map<String, Object> errResponse = error.code() == UNSUPPORTED_PROTOCOL_VERSION
              ? mcpErrorResponse(exchange, error.id(), error.code(), error.getMessage(),
                  Map.of("requested", error.requestedVersion(), "supported", SUPPORTED_PROTOCOL_VERSIONS))
              : mcpErrorResponse(exchange, error.id(), error.code(), error.getMessage(), null);
          String querySessionId = getQueryParameter(exchange.getRequestURI(), SESSION_ID_PARAM);
          SseSession activeSse = querySessionId == null ? null : sseSessions.get(querySessionId);
          if (activeSse != null && activeSse.isActive()) {
            try {
              activeSse.sendEvent("message", JsonUtil.toJson(errResponse));
            } catch (IOException ignored) {}
            if (error.httpStatus() == HTTP_PAYLOAD_TOO_LARGE) {
              writeJson(exchange, error.httpStatus(), errResponse);
            } else {
              exchange.sendResponseHeaders(202, -1);
            }
          } else {
            writeJson(exchange, error.httpStatus(), errResponse);
          }
        } catch (IOException | RuntimeException error) {
          log.error().status(500).cause(rootMessage(error));
          writeJsonRpcError(exchange, 500, null, JSONRPC_INTERNAL_ERROR, "Internal error");
        } finally {
          log.finish();
        }
      }
    }

    private void handleSseGet(HttpExchange exchange, RequestLog log) throws IOException {
      String sessionId = UUID.randomUUID().toString();
      SseSession session;
      try {
        session = new SseSession(sessionId, exchange);
      } catch (IOException error) {
        log.method(HTTP_GET_METHOD).error().status(500);
        return;
      }
      sseSessions.put(sessionId, session);
      log.method(HTTP_GET_METHOD).ok().status(200);

      try {
        String endpointUri = config.path() + "?" + SESSION_ID_PARAM + "=" + sessionId;
        session.sendEvent("endpoint", endpointUri);

        while (session.isActive() && !closed.get()) {
          try {
            if (session.awaitClose(sseKeepaliveMillis, TimeUnit.MILLISECONDS)) {
              break;
            }
            if (closed.get()) {
              break;
            }
            session.sendComment("keepalive");
          } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            break;
          }
        }
      } catch (IOException clientDisconnected) {
        // The SSE client disconnected.
      } finally {
        sseSessions.remove(sessionId);
        session.closeAndAwaitStream();
      }
    }
  }

  private Object handleRequest(
      Map<String, Object> request, Object id, RequestLog log, boolean statelessProtocol) {
    String method = request.get("method").toString();
    log.method(method);
    if (!request.containsKey("id")) {
      return null;
    }
    Object params = request.get("params");
    log.id(id);

    return switch (method) {
      case "initialize" -> {
        if (statelessProtocol) {
          throw new JsonRpcError(404, id, JSONRPC_METHOD_NOT_FOUND, "Method not found: " + method);
        }
        Map<String, Object> result = initializeResult(id, requireParamsMap(params, id));
        log.ok().status(200);
        yield success(id, result);
      }
      case "server/discover" -> {
        log.ok().status(200);
        yield success(id, discoveryResult());
      }
      case "ping" -> {
        log.ok().status(200);
        yield success(id, statelessProtocol ? Map.of("resultType", "complete") : Map.of());
      }
      case "tools/list" -> {
        log.ok().status(200);
        yield success(id, statelessProtocol
            ? cacheableResult(Map.of("resultType", "complete", "tools", toolRegistry.listTools()), true)
            : Map.of("tools", toolRegistry.listTools()));
      }
      case "resources/list" -> {
        log.ok().status(200);
        yield success(id, statelessProtocol
            ? cacheableResult(Map.of("resultType", "complete", "resources", List.of(mcpToolsResource())), true)
            : Map.of("resources", List.of(mcpToolsResource())));
      }
      case "resources/templates/list" -> {
        log.ok().status(200);
        yield success(id, statelessProtocol
            ? cacheableResult(Map.of("resultType", "complete", "resourceTemplates", List.of()), true)
            : Map.of("resourceTemplates", List.of()));
      }
      case "resources/read" -> {
        log.ok().status(200);
        yield success(id, cacheableResult(
            readResource(id, requireParamsMap(params, id), statelessProtocol), statelessProtocol));
      }
      case "tools/call" -> {
        yield success(id, handleToolCall(id, requireParamsMap(params, id), log, statelessProtocol));
      }
      default ->
          throw new JsonRpcError(404, id, JSONRPC_METHOD_NOT_FOUND, "Method not found: " + method);
    };
  }

  private Map<String, Object> initializeResult(Object id, Map<String, Object> params) {
    if (!(params.get("protocolVersion") instanceof String requestedVersion)) {
      throw new JsonRpcError(400, id, JSONRPC_INVALID_PARAMS, "protocolVersion must be a string");
    }
    if (!(params.get("capabilities") instanceof Map<?, ?>)) {
      throw new JsonRpcError(400, id, JSONRPC_INVALID_PARAMS, "capabilities must be a JSON object");
    }
    validateImplementation(params.get("clientInfo"), id);
    Map<String, Object> discovery = discoveryResult();
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("protocolVersion", INITIALIZE_PROTOCOL_VERSIONS.contains(requestedVersion)
        ? requestedVersion : INITIALIZE_PROTOCOL_VERSION);
    result.put("capabilities", discovery.get("capabilities"));
    result.put("serverInfo", Map.of(NAME_FIELD, "ghidra-bridge", "version", serverVersion()));
    result.put("instructions", discovery.get("instructions"));
    return result;
  }

  private Map<String, Object> discoveryResult() {
    Map<String, Object> capabilities = new LinkedHashMap<>();
    capabilities.put("tools", Map.of("listChanged", false));
    capabilities.put("resources", Map.of("listChanged", false));

    Map<String, Object> serverInfo = new LinkedHashMap<>();
    serverInfo.put(NAME_FIELD, "ghidra-bridge");
    serverInfo.put("version", serverVersion());

    Map<String, Object> result = new LinkedHashMap<>();
    result.put("resultType", "complete");
    result.put("supportedVersions", SUPPORTED_PROTOCOL_VERSIONS);
    result.put("capabilities", capabilities);
    result.put("_meta", Map.of("io.modelcontextprotocol/serverInfo", serverInfo));
    result.put(
        "instructions",
        "Use tools/list for the current callable contract, then tools/call to interact with the"
            + " active Ghidra program. The same tool contract is readable as an MCP resource.");
    return cacheableResult(result, true);
  }

  private static Map<String, Object> cacheableResult(
      Map<String, Object> result, boolean statelessProtocol) {
    if (!statelessProtocol) return result;
    Map<String, Object> cached = new LinkedHashMap<>(result);
    cached.put("ttlMs", 0);
    cached.put("cacheScope", "private");
    return cached;
  }

  private Map<String, Object> mcpToolsResource() {
    Map<String, Object> resource = new LinkedHashMap<>();
    resource.put(URI_FIELD, MCP_TOOLS_RESOURCE_URI);
    resource.put(NAME_FIELD, "mcp-tools");
    resource.put("title", "Ghidra Bridge MCP tool contract");
    resource.put("description", "The current callable Ghidra Bridge tool catalog and schemas.");
    resource.put("mimeType", "application/json");
    return resource;
  }

  private Map<String, Object> readResource(
      Object id, Map<String, Object> params, boolean statelessProtocol) {
    String uri = requireString(params.get(URI_FIELD), URI_FIELD, id);
    if (!MCP_TOOLS_RESOURCE_URI.equals(uri)) {
      throw new JsonRpcError(statelessProtocol ? 400 : 404, id,
          statelessProtocol ? JSONRPC_INVALID_PARAMS : JSONRPC_RESOURCE_NOT_FOUND,
          "Resource not found: " + uri);
    }
    Map<String, Object> content = new LinkedHashMap<>();
    content.put(URI_FIELD, MCP_TOOLS_RESOURCE_URI);
    content.put("mimeType", "application/json");
    content.put("text", toolContractJson);
    return statelessProtocol
        ? Map.of("resultType", "complete", "contents", List.of(content))
        : Map.of("contents", List.of(content));
  }

  private Map<String, Object> handleToolCall(
      Object id, Map<String, Object> params, RequestLog log, boolean statelessProtocol) {
    String name = requireString(params.get(NAME_FIELD), NAME_FIELD, id);
    log.tool(name);
    if (!toolRegistry.hasTool(name)) {
      throw new JsonRpcError(400, id, JSONRPC_INVALID_PARAMS, "Unknown tool: " + name);
    }
    Map<String, Object> arguments = requireArguments(params.get("arguments"), id);
    try {
      if (toolRegistry.isHelpTool(name)) {
        log.ok().status(200);
        return toolResult(toolRegistry.help(arguments), false, statelessProtocol);
      }
      if (!List.of("operation", "params").containsAll(arguments.keySet())) {
        throw new IllegalArgumentException("Unknown domain tool argument");
      }
      String operation = requireString(arguments.get("operation"), "operation", id);
      MethodDescriptor tool = toolRegistry.findTool(name, operation);
      if (tool == null) {
        throw new JsonRpcError(400, id, JSONRPC_INVALID_PARAMS,
            "Unknown operation " + operation + " for " + name);
      }
      Map<String, Object> operationParams = requireArguments(arguments.get("params"), id);
      Object result = dispatcher.dispatch(tool.name(), operationParams);
      if (dispatcher.isShuttingDown()) {
        closeSoon();
      }
      log.ok().status(200);
      return toolResult(Map.of("operation", operation, "result", result), false, statelessProtocol);
    } catch (Exception error) {
      log.error().status(200);
      return toolResult(errorPayload(error), true, statelessProtocol);
    }
  }

  static Map<String, Object> toolResult(
      Object result, boolean isError, boolean statelessProtocol) {
    Map<String, Object> content = new LinkedHashMap<>();
    content.put("type", "text");
    Object structured;
    if (result instanceof String string) {
      content.put("text", string);
      structured = structuredContent(result, string);
    } else {
      String json = JsonUtil.toJson(result);
      content.put("text", json);
      structured = structuredContent(result, JsonUtil.rawJson(json));
    }

    Map<String, Object> response = new LinkedHashMap<>();
    if (statelessProtocol) {
      response.put("resultType", "complete");
    }
    response.put("content", List.of(content));
    response.put("structuredContent", structured);
    response.put("isError", isError);
    return response;
  }

  private static Object structuredContent(Object original, Object encoded) {
    if (original instanceof Map<?, ?>) {
      return encoded;
    }
    Map<String, Object> wrapper = new LinkedHashMap<>();
    wrapper.put("value", encoded);
    return wrapper;
  }

  static Map<String, Object> errorPayload(Exception exception) {
    return ApiFailures.normalize(exception).error().toMap();
  }

  private void closeSoon() {
    Thread shutdownThread =
        new Thread(
            () -> {
              try {
                Thread.sleep(100L);
              } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
              }
              close();
            },
            "ghidra-mcp-shutdown");
    shutdownThread.setDaemon(true);
    shutdownThread.start();
  }

  private static Map<String, Object> parseRequest(String body) {
    try {
      Object parsed = JsonUtil.parse(body);
      if (!(parsed instanceof Map<?, ?> map)) {
        throw new JsonRpcError(400, null, JSONRPC_INVALID_REQUEST, "Request must be a JSON object");
      }
      @SuppressWarnings("unchecked")
      Map<String, Object> cast = (Map<String, Object>) map;
      return cast;
    } catch (JsonRpcError error) {
      throw error;
    } catch (IllegalArgumentException error) {
      throw new JsonRpcError(400, null, JSONRPC_PARSE_ERROR, "Invalid JSON request body", error);
    }
  }

  private static void validateJsonRpcEnvelope(Map<String, Object> request) {
    if (request.containsKey("id") && !isRequestId(request.get("id"))) {
      throw new JsonRpcError(400, null, JSONRPC_INVALID_REQUEST,
          "id must be a string or integer");
    }
    if (!JsonRpc.isVersion(request.get("jsonrpc"))) {
      throw new JsonRpcError(
          400, request.get("id"), JSONRPC_INVALID_REQUEST, "jsonrpc must be \"2.0\"");
    }
    if (!(request.get("method") instanceof String method) || method.isBlank()) {
      throw new JsonRpcError(
          400, request.get("id"), JSONRPC_INVALID_REQUEST, "method must be a non-empty string");
    }
  }

  private static boolean isRequestId(Object id) {
    return id instanceof String || (id instanceof Number number
        && Double.isFinite(number.doubleValue())
        && number.doubleValue() == Math.rint(number.doubleValue()));
  }

  private static boolean usesStatelessProtocol(
      HttpExchange exchange, Map<String, Object> request) {
    Map<String, Object> params = requireParamsMap(request.get("params"), request.get("id"));
    if (params.get("_meta") instanceof Map<?, ?> meta
        && (meta.containsKey("io.modelcontextprotocol/protocolVersion")
            || meta.containsKey("io.modelcontextprotocol/clientInfo")
            || meta.containsKey("io.modelcontextprotocol/clientCapabilities"))) {
      return true;
    }
    // Initialization negotiates its version in params before the HTTP headers control it.
    return !"initialize".equals(request.get("method"))
        && (MCP_PROTOCOL_VERSION.equals(firstHeader(exchange, "MCP-Protocol-Version"))
            || "server/discover".equals(request.get("method")));
  }

  private static void validateInitializeProtocol(
      HttpExchange exchange, Map<String, Object> request) {
    String version = firstHeader(exchange, "MCP-Protocol-Version");
    if (version == null
        || SUPPORTED_PROTOCOL_VERSIONS.contains(version)
        || INITIALIZE_PROTOCOL_VERSIONS.contains(version)) {
      return;
    }
    throw new JsonRpcError(400, request.get("id"), JSONRPC_INVALID_REQUEST,
        "Missing or unsupported MCP-Protocol-Version: " + version);
  }

  private static void validateMetadata(HttpExchange exchange, Map<String, Object> request) {
    Object id = request.get("id");
    Map<String, Object> params = requireParamsMap(request.get("params"), id);
    if (!(params.get("_meta") instanceof Map<?, ?> meta)
        || !(meta.get("io.modelcontextprotocol/protocolVersion") instanceof String)
        || !(meta.get("io.modelcontextprotocol/clientCapabilities") instanceof Map<?, ?>)) {
      throw new JsonRpcError(400, id, JSONRPC_INVALID_PARAMS, "Missing MCP request metadata");
    }
    if (meta.containsKey("io.modelcontextprotocol/clientInfo")) {
      validateImplementation(meta.get("io.modelcontextprotocol/clientInfo"), id);
    }
    Object version = meta.get("io.modelcontextprotocol/protocolVersion");
    if (!MCP_PROTOCOL_VERSION.equals(version)) {
      throw new JsonRpcError(400, id, UNSUPPORTED_PROTOCOL_VERSION,
          "UnsupportedProtocolVersionError", String.valueOf(version));
    }
    requireHeader(exchange, "MCP-Protocol-Version", version.toString(), id);
    Object method = request.get("method");
    if (!(method instanceof String)) {
      throw new JsonRpcError(400, id, JSONRPC_INVALID_REQUEST, "Missing method");
    }
    requireHeader(exchange, "Mcp-Method", method.toString(), id);
    if (method.equals("tools/call") || method.equals("resources/read")) {
      String key = method.equals("tools/call") ? "name" : "uri";
      Object name = params.get(key);
      requireHeader(exchange, "Mcp-Name", name == null ? "" : name.toString(), id);
    }
  }

  private static void validateImplementation(Object value, Object id) {
    if (value == null) {
      return;
    }
    if (!(value instanceof Map<?, ?> info)
        || !(info.get(NAME_FIELD) instanceof String)
        || !(info.get("version") instanceof String)) {
      throw new JsonRpcError(400, id, JSONRPC_INVALID_PARAMS,
          "clientInfo must contain string name and version fields");
    }
  }

  private static void requireHeader(HttpExchange exchange, String header, String expected, Object id) {
    String actual = firstHeader(exchange, header);
    if (actual != null && actual.startsWith("=?base64?") && actual.endsWith("?=")) {
      try {
        actual = new String(java.util.Base64.getDecoder().decode(
            actual.substring(9, actual.length() - 2)), StandardCharsets.UTF_8);
      } catch (IllegalArgumentException invalid) {
        throw new JsonRpcError(400, id, HEADER_MISMATCH, "Invalid " + header + " encoding");
      }
    }
    if (!expected.equals(actual)) {
      throw new JsonRpcError(400, id, HEADER_MISMATCH, "HeaderMismatch: " + header);
    }
  }

  private static Map<String, Object> requireParamsMap(Object params, Object id) {
    if (params == null) {
      return Map.of();
    }
    if (params instanceof Map<?, ?> map) {
      @SuppressWarnings("unchecked")
      Map<String, Object> cast = (Map<String, Object>) map;
      return cast;
    }
    throw new JsonRpcError(400, id, JSONRPC_INVALID_PARAMS, "params must be a JSON object");
  }

  private static Map<String, Object> requireArguments(Object arguments, Object id) {
    if (arguments == null) {
      return Map.of();
    }
    if (arguments instanceof Map<?, ?> map) {
      @SuppressWarnings("unchecked")
      Map<String, Object> cast = (Map<String, Object>) map;
      return cast;
    }
    throw new JsonRpcError(
        400, id, JSONRPC_INVALID_PARAMS, "tools/call arguments must be a JSON object");
  }

  private static String requireString(Object value, String field, Object id) {
    if (value instanceof String text && !text.isBlank()) {
      return text;
    }
    throw new JsonRpcError(400, id, JSONRPC_INVALID_PARAMS, field + " must be a non-empty string");
  }

  private boolean authorize(HttpExchange exchange) {
    String expectedToken = config.token();
    if (expectedToken == null) {
      return true;
    }
    return NetworkBinding.bearerTokenMatches(
        exchange.getRequestHeaders().getFirst("Authorization"), expectedToken);
  }

  private static boolean hasQueryToken(URI uri) {
    String query = uri.getQuery();
    if (query == null || query.isBlank()) return false;
    int parameterStart = 0;
    while (parameterStart <= query.length()) {
      int parameterEnd = query.indexOf('&', parameterStart);
      if (parameterEnd < 0) parameterEnd = query.length();
      int valueSeparator = query.indexOf('=', parameterStart);
      int nameEnd =
          valueSeparator >= parameterStart && valueSeparator < parameterEnd
              ? valueSeparator
              : parameterEnd;
      if (nameEnd - parameterStart == "token".length()
          && query.startsWith("token", parameterStart)) {
        return true;
      }
      if (parameterEnd == query.length()) return false;
      parameterStart = parameterEnd + 1;
    }
    return false;
  }

  private static void discardRequestLog(String ignored) {}

  static void validateContentLength(Headers headers) {
    List<String> values = headers == null ? null : headers.get("Content-Length");
    if (values == null || values.isEmpty()) {
      return;
    }
    if (values.size() > 1) {
      throw new JsonRpcError(
          400, null, JSONRPC_INVALID_REQUEST, "Duplicate Content-Length header");
    }
    String raw = values.get(0);
    if (raw == null) {
      throw new JsonRpcError(
          400, null, JSONRPC_INVALID_REQUEST, "Invalid Content-Length header");
    }
    String trimmed = raw.trim();
    if (trimmed.isEmpty() || !isAsciiDigits(trimmed)) {
      throw new JsonRpcError(
          400, null, JSONRPC_INVALID_REQUEST, "Invalid Content-Length header");
    }
    long contentLength;
    try {
      contentLength = Long.parseLong(trimmed);
    } catch (NumberFormatException error) {
      throw new JsonRpcError(
          400, null, JSONRPC_INVALID_REQUEST, "Invalid Content-Length header", error);
    }
    if (contentLength > MAX_REQUEST_BODY_BYTES) {
      throw new JsonRpcError(
          HTTP_PAYLOAD_TOO_LARGE,
          null,
          JSONRPC_INVALID_REQUEST,
          "Request body exceeds maximum size of " + MAX_REQUEST_BODY_BYTES + " bytes");
    }
  }

  private static boolean isAsciiDigits(String value) {
    for (int i = 0; i < value.length(); i++) {
      char ch = value.charAt(i);
      if (ch < '0' || ch > '9') {
        return false;
      }
    }
    return true;
  }

  static String readBody(HttpExchange exchange) throws IOException {
    InputStream input = exchange.getRequestBody();
    // Guard len == 0 because jdk.httpserver's ChunkedInputStream reads the next chunk header on a
    // zero-length read after InputStream.readNBytes fills its final buffer.
    InputStream boundedView =
        new FilterInputStream(input) {
          @Override
          public int read(byte[] buf, int off, int len) throws IOException {
            return len == 0 ? 0 : in.read(buf, off, len);
          }
        };
    byte[] bytes = boundedView.readNBytes(MAX_REQUEST_BODY_BYTES + 1);
    if (bytes.length > MAX_REQUEST_BODY_BYTES) {
      throw new JsonRpcError(
          HTTP_PAYLOAD_TOO_LARGE,
          null,
          JSONRPC_INVALID_REQUEST,
          "Request body exceeds maximum size of " + MAX_REQUEST_BODY_BYTES + " bytes");
    }
    input.close();
    return new String(bytes, StandardCharsets.UTF_8);
  }

  private static void writeJsonRpcError(
      HttpExchange exchange, int httpStatus, Object id, int code, String message)
      throws IOException {
    writeJson(exchange, httpStatus, mcpErrorResponse(exchange, id, code, message, null));
  }

  private static Map<String, Object> mcpErrorResponse(
      HttpExchange exchange, Object id, int code, String message, Map<String, Object> data) {
    Map<String, Object> response = data == null
        ? JsonRpc.errorResponse(id, code, message)
        : JsonRpc.errorResponse(id, code, message, data);
    if (!isRequestId(id)) {
      // The June error schema cannot express an unknown ID.
      // Follow the JSON-RPC null ID rule.
      if ("2025-06-18".equals(firstHeader(exchange, "MCP-Protocol-Version"))) {
        response.put("id", null);
      } else {
        response.remove("id");
      }
    }
    return response;
  }

  private static Map<String, Object> success(Object id, Object result) {
    return JsonRpc.success(id, result);
  }

  private static void writeJson(HttpExchange exchange, int statusCode, Object payload)
      throws IOException {
    byte[] bytes = JsonUtil.toJson(payload).getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
    exchange.sendResponseHeaders(statusCode, bytes.length);
    try (OutputStream output = exchange.getResponseBody()) {
      output.write(bytes);
    }
  }

  private static void writePlain(HttpExchange exchange, int statusCode, String payload)
      throws IOException {
    byte[] bytes = payload.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
    if ("HEAD".equalsIgnoreCase(exchange.getRequestMethod())) {
      exchange.sendResponseHeaders(statusCode, -1);
      return;
    }
    exchange.sendResponseHeaders(statusCode, bytes.length);
    try (OutputStream output = exchange.getResponseBody()) {
      output.write(bytes);
    }
  }

  private NetworkBinding.HostValidationResult validateHost(HttpExchange exchange) {
    List<String> hostHeaders = exchange.getRequestHeaders().get("Host");
    return NetworkBinding.validateHostHeader(
        hostHeaders, config.host(), server.getAddress().getPort(), loopbackListener);
  }

  private static void sendNoBody(HttpExchange exchange, int statusCode) throws IOException {
    exchange.sendResponseHeaders(statusCode, -1);
  }

  private void addCommonHeaders(HttpExchange exchange, String validatedOrigin) {
    if (validatedOrigin != null) {
      exchange.getResponseHeaders().set("Access-Control-Allow-Origin", validatedOrigin);
      exchange.getResponseHeaders().set("Vary", "Origin");
    }
    exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, HEAD, OPTIONS");
    exchange
        .getResponseHeaders()
        .set("Access-Control-Allow-Headers", "Authorization, Content-Type, MCP-Protocol-Version, Mcp-Method, Mcp-Name, Accept");
    exchange
        .getResponseHeaders()
        .set("Access-Control-Expose-Headers", "MCP-Protocol-Version");
  }

  private record OriginValidation(boolean allowed, String origin) {
    static final OriginValidation ABSENT_ALLOWED = new OriginValidation(true, null);
    static final OriginValidation REJECTED = new OriginValidation(false, null);
  }

  private OriginValidation validateOrigin(HttpExchange exchange) {
    return validateOriginHeaders(
        exchange.getRequestHeaders().get("Origin"),
        normalizedConfiguredHost,
        configuredHostLiteral);
  }

  boolean isAllowedOrigin(HttpExchange exchange) {
    return validateOrigin(exchange).allowed();
  }

  static boolean isAllowedOrigin(List<String> originHeaders, String configuredHost) {
    String normalizedConfigHost = normalizeHost(Objects.requireNonNull(configuredHost, "configuredHost"));
    return validateOriginHeaders(
            originHeaders, normalizedConfigHost, parseIpLiteral(normalizedConfigHost))
        .allowed();
  }

  private static OriginValidation validateOriginHeaders(
      List<String> values, String normalizedConfigHost, InetAddress configHostLiteral) {
    if (values == null || values.isEmpty()) {
      return OriginValidation.ABSENT_ALLOWED;
    }
    if (values.size() != 1) {
      return OriginValidation.REJECTED;
    }
    String rawOrigin = values.get(0);
    if (rawOrigin == null) {
      return OriginValidation.REJECTED;
    }
    String origin = rawOrigin.trim();
    if (origin.isEmpty()
        || "null".equalsIgnoreCase(origin)
        || origin.indexOf(',') >= 0
        || origin.indexOf('?') >= 0
        || origin.indexOf('#') >= 0) {
      return OriginValidation.REJECTED;
    }

    final URI uri;
    try {
      uri = URI.create(origin);
    } catch (IllegalArgumentException invalidOrigin) {
      return OriginValidation.REJECTED;
    }

    String scheme = uri.getScheme();
    if (scheme == null
        || (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme))
        || uri.isOpaque()) {
      return OriginValidation.REJECTED;
    }

    String rawAuthority = uri.getRawAuthority();
    if (rawAuthority == null
        || rawAuthority.isEmpty()
        || uri.getRawUserInfo() != null
        || uri.getUserInfo() != null
        || rawAuthority.indexOf('@') >= 0
        || rawAuthority.endsWith(":")) {
      return OriginValidation.REJECTED;
    }

    int port = uri.getPort();
    if (port != -1 && (port < 1 || port > 65535)) {
      return OriginValidation.REJECTED;
    }

    String rawPath = uri.getRawPath();
    if ((rawPath != null && !rawPath.isEmpty())
        || uri.getRawQuery() != null
        || uri.getRawFragment() != null) {
      return OriginValidation.REJECTED;
    }

    String rawHost = uri.getHost();
    if (rawHost == null || rawHost.isBlank()) {
      return OriginValidation.REJECTED;
    }

    String normalizedOriginHost = normalizeHost(rawHost);
    if (normalizedOriginHost.isEmpty()) {
      return OriginValidation.REJECTED;
    }

    if ("localhost".equals(normalizedOriginHost)
        || normalizedOriginHost.equals(normalizedConfigHost)) {
      return new OriginValidation(true, origin);
    }

    InetAddress originLiteral = parseIpLiteral(normalizedOriginHost);
    if (originLiteral != null
        && (originLiteral.isLoopbackAddress() || originLiteral.equals(configHostLiteral))) {
      return new OriginValidation(true, origin);
    }

    return OriginValidation.REJECTED;
  }

  static String normalizeHost(String host) {
    String trimmed = host.trim();
    if (trimmed.length() > 2
        && trimmed.charAt(0) == '['
        && trimmed.charAt(trimmed.length() - 1) == ']'
        && trimmed.indexOf(':') >= 0) {
      trimmed = trimmed.substring(1, trimmed.length() - 1);
    }
    return trimmed.toLowerCase(Locale.ROOT);
  }

  static InetAddress parseIpLiteral(String literal) {
    if (literal == null || literal.isEmpty()) {
      return null;
    }
    byte[] bytes = literal.indexOf(':') >= 0 ? parseIpv6Bytes(literal) : parseIpv4Bytes(literal);
    if (bytes == null) {
      return null;
    }
    try {
      return InetAddress.getByAddress(bytes);
    } catch (UnknownHostException impossible) {
      return null;
    }
  }

  private static byte[] parseIpv4Bytes(String literal) {
    byte[] bytes = new byte[4];
    int octetIndex = 0;
    int value = 0;
    int digits = 0;
    for (int i = 0; i < literal.length(); i++) {
      char ch = literal.charAt(i);
      if (ch == '.') {
        if (digits == 0 || octetIndex == 3) {
          return null;
        }
        bytes[octetIndex++] = (byte) value;
        value = 0;
        digits = 0;
      } else if (ch >= '0' && ch <= '9') {
        if (digits == 1 && value == 0) {
          return null;
        }
        value = value * 10 + (ch - '0');
        digits++;
        if (digits > 3 || value > 255) {
          return null;
        }
      } else {
        return null;
      }
    }
    if (digits == 0 || octetIndex != 3) {
      return null;
    }
    bytes[3] = (byte) value;
    return bytes;
  }

  private static byte[] parseIpv6Bytes(String literal) {
    if (literal.length() < 2 || literal.indexOf('%') >= 0) {
      return null;
    }
    int doubleColon = literal.indexOf("::");
    if (doubleColon >= 0 && literal.indexOf("::", doubleColon + 1) >= 0) {
      return null;
    }
    String headPart = doubleColon >= 0 ? literal.substring(0, doubleColon) : literal;
    String tailPart = doubleColon >= 0 ? literal.substring(doubleColon + 2) : null;

    byte[] headBytes =
        headPart.isEmpty() ? new byte[0] : parseIpv6Groups(headPart, tailPart == null);
    if (headBytes == null || (doubleColon < 0 && headPart.isEmpty())) {
      return null;
    }
    if (tailPart == null) {
      return headBytes.length == 16 ? headBytes : null;
    }
    byte[] tailBytes = tailPart.isEmpty() ? new byte[0] : parseIpv6Groups(tailPart, true);
    if (tailBytes == null || headBytes.length + tailBytes.length >= 16) {
      return null;
    }
    byte[] result = new byte[16];
    System.arraycopy(headBytes, 0, result, 0, headBytes.length);
    System.arraycopy(tailBytes, 0, result, 16 - tailBytes.length, tailBytes.length);
    return result;
  }

  private static byte[] parseIpv6Groups(String part, boolean allowTrailingIpv4) {
    if (part.charAt(0) == ':' || part.charAt(part.length() - 1) == ':') {
      return null;
    }
    String[] groups = part.split(":", -1);
    byte[] buffer = new byte[16];
    int offset = 0;
    for (int i = 0; i < groups.length; i++) {
      String group = groups[i];
      if (group.isEmpty()) {
        return null;
      }
      if (group.indexOf('.') >= 0) {
        if (!allowTrailingIpv4 || i != groups.length - 1 || offset > 12) {
          return null;
        }
        byte[] ipv4 = parseIpv4Bytes(group);
        if (ipv4 == null) {
          return null;
        }
        System.arraycopy(ipv4, 0, buffer, offset, 4);
        offset += 4;
      } else {
        if (group.length() > 4 || offset > 14) {
          return null;
        }
        int word = 0;
        for (int j = 0; j < group.length(); j++) {
          int digit = asciiHexDigit(group.charAt(j));
          if (digit < 0) {
            return null;
          }
          word = (word << 4) | digit;
        }
        buffer[offset++] = (byte) (word >>> 8);
        buffer[offset++] = (byte) word;
      }
    }
    return Arrays.copyOf(buffer, offset);
  }

  private static int asciiHexDigit(char ch) {
    if (ch >= '0' && ch <= '9') {
      return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
      return ch - 'a' + 10;
    }
    if (ch >= 'A' && ch <= 'F') {
      return ch - 'A' + 10;
    }
    return -1;
  }

  private static String firstHeader(HttpExchange exchange, String name) {
    List<String> values = exchange.getRequestHeaders().get(name);
    return values == null || values.isEmpty() ? null : values.get(0);
  }

  private static String serverVersion() {
    String version = McpHttpServer.class.getPackage().getImplementationVersion();
    return version == null || version.isBlank() ? "0.0.0-dev" : version;
  }

  private static String rootMessage(Throwable error) {
    Throwable current = error;
    while (current.getCause() != null) {
      current = current.getCause();
    }
    String message = current.getMessage();
    return message == null || message.isBlank() ? current.getClass().getName() : message;
  }

  static final class JsonRpcError extends RuntimeException {
    private static final long serialVersionUID = 1L;
    private final int statusCode;
    private final transient Object requestId;
    private final int errorCode;
    private final String requestedVersion;

    JsonRpcError(int httpStatus, Object id, int code, String message) {
      this(httpStatus, id, code, message, (Throwable) null);
    }

    JsonRpcError(int httpStatus, Object id, int code, String message, Throwable cause) {
      super(message, cause);
      this.statusCode = httpStatus;
      this.requestId = id;
      this.errorCode = code;
      this.requestedVersion = null;
    }

    JsonRpcError(int httpStatus, Object id, int code, String message, String requestedVersion) {
      super(message);
      this.statusCode = httpStatus;
      this.requestId = id;
      this.errorCode = code;
      this.requestedVersion = requestedVersion;
    }

    int httpStatus() {
      return statusCode;
    }

    Object id() {
      return requestId;
    }

    int code() {
      return errorCode;
    }

    String requestedVersion() {
      return requestedVersion;
    }
  }

  private static String getQueryParameter(URI uri, String name) {
    String query = uri.getRawQuery();
    if (query == null || query.isBlank()) {
      return null;
    }
    for (String pair : query.split("&")) {
      int eq = pair.indexOf('=');
      String key = eq >= 0 ? pair.substring(0, eq) : pair;
      if (key.equals(name)) {
        return eq >= 0
            ? java.net.URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8)
            : "";
      }
    }
    return null;
  }

  static final class SseSession implements AutoCloseable {
    private final String id;
    private final HttpExchange exchange;
    private final OutputStream output;
    private final AtomicBoolean active = new AtomicBoolean(true);
    private final AtomicBoolean streamClosed = new AtomicBoolean(false);
    private final CountDownLatch closeLatch = new CountDownLatch(1);
    private final ReentrantLock writeLock = new ReentrantLock();

    SseSession(String id, HttpExchange exchange) throws IOException {
      this.id = id;
      this.exchange = exchange;
      exchange.getResponseHeaders().set("Content-Type", "text/event-stream; charset=utf-8");
      exchange.getResponseHeaders().set("Cache-Control", "no-cache, no-transform");
      exchange.getResponseHeaders().set("Connection", "keep-alive");
      exchange.getResponseHeaders().set("X-Accel-Buffering", "no");
      exchange.sendResponseHeaders(200, 0);
      this.output = exchange.getResponseBody();
    }

    void sendEvent(String event, String data) throws IOException {
      writeLock.lock();
      try {
        if (!active.get()) {
          return;
        }
        StringBuilder sb = new StringBuilder();
        if (event != null && !event.isBlank()) {
          sb.append("event: ").append(event).append("\n");
        }
        for (String line : data.split("\r?\n")) {
          sb.append("data: ").append(line).append("\n");
        }
        sb.append("\n");
        output.write(sb.toString().getBytes(StandardCharsets.UTF_8));
        output.flush();
      } finally {
        writeLock.unlock();
      }
    }

    void sendComment(String comment) throws IOException {
      writeLock.lock();
      try {
        if (!active.get()) {
          return;
        }
        String payload = ": " + comment + "\n\n";
        output.write(payload.getBytes(StandardCharsets.UTF_8));
        output.flush();
      } finally {
        writeLock.unlock();
      }
    }

    boolean awaitClose(long timeout, TimeUnit unit) throws InterruptedException {
      return closeLatch.await(timeout, unit);
    }

    @Override
    public void close() {
      active.set(false);
      closeLatch.countDown();
      if (writeLock.tryLock()) {
        try {
          closeStream();
        } finally {
          writeLock.unlock();
        }
      }
    }

    void closeAndAwaitStream() {
      active.set(false);
      closeLatch.countDown();
      boolean interrupted = Thread.interrupted();
      writeLock.lock();
      try {
        closeStream();
      } finally {
        writeLock.unlock();
        if (interrupted) {
          Thread.currentThread().interrupt();
        }
      }
    }

    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    private void closeStream() {
      if (!streamClosed.compareAndSet(false, true)) {
        return;
      }
      try {
        output.close();
      } catch (IOException ignored) {}
      try {
        exchange.close();
      } catch (Exception ignored) {}
    }

    boolean isActive() {
      return active.get();
    }
  }
}
