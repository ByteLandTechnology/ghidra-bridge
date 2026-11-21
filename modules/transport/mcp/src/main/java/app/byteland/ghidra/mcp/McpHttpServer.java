package app.byteland.ghidra.mcp;

import app.byteland.ghidra.ExecutorShutdown;
import app.byteland.ghidra.JsonRpc;
import app.byteland.ghidra.JsonUtil;
import app.byteland.ghidra.agent.AgentDispatcher;
import app.byteland.ghidra.api.ApiCatalog.MethodDescriptor;
import app.byteland.ghidra.api.ApiFailures;
import app.byteland.ghidra.network.NetworkBinding;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.BindException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/**
 * HTTP server that exposes the bridge API as grouped MCP tools through Streamable HTTP and SSE.
 */
public final class McpHttpServer implements AutoCloseable {
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
  static final int MAX_REQUEST_BODY_BYTES = 4 * 1024 * 1024;
  private static final long BODY_DRAIN_LIMIT_BYTES = 16L * 1024 * 1024;
  private static final int READ_CHUNK_BYTES = 8192;
  static final int DEFAULT_MAX_SSE_SESSIONS = 16;
  private static final long DEFAULT_SSE_KEEPALIVE_MILLIS = 15_000L;

  private final McpConfig config;
  private final AgentDispatcher dispatcher;
  private final Consumer<String> requestLogSink;
  private final McpToolRegistry toolRegistry;
  private final String toolContractJson;
  private final HttpServer server;
  private final ExecutorService executor;
  private final Semaphore sseSessionSlots;
  private final long sseKeepaliveMillis;
  private final CountDownLatch shutdownLatch = new CountDownLatch(1);
  private final AtomicBoolean closed = new AtomicBoolean(false);
  private final ConcurrentHashMap<String, SseSession> sseSessions = new ConcurrentHashMap<>();

  public McpHttpServer(McpConfig config, AgentDispatcher dispatcher) throws IOException {
    this(
        config,
        dispatcher,
        McpHttpServer::discardRequestLog,
        DEFAULT_MAX_SSE_SESSIONS,
        DEFAULT_SSE_KEEPALIVE_MILLIS);
  }

  public McpHttpServer(
      McpConfig config, AgentDispatcher dispatcher, Consumer<String> requestLogSink)
      throws IOException {
    this(
        config,
        dispatcher,
        requestLogSink,
        DEFAULT_MAX_SSE_SESSIONS,
        DEFAULT_SSE_KEEPALIVE_MILLIS);
  }

  McpHttpServer(
      McpConfig config,
      AgentDispatcher dispatcher,
      Consumer<String> requestLogSink,
      int maxSseSessions,
      long sseKeepaliveMillis)
      throws IOException {
    if (maxSseSessions < 1) {
      throw new IllegalArgumentException("maxSseSessions must be positive");
    }
    if (sseKeepaliveMillis < 1L) {
      throw new IllegalArgumentException("sseKeepaliveMillis must be positive");
    }
    this.config = Objects.requireNonNull(config, "config");
    this.dispatcher = Objects.requireNonNull(dispatcher, "dispatcher");
    this.requestLogSink = Objects.requireNonNull(requestLogSink, "requestLogSink");
    this.toolRegistry = new McpToolRegistry(dispatcher.methodCatalog(), config.toolPrefix());
    Map<String, Object> toolContract = new LinkedHashMap<>();
    toolContract.put("protocol_version", MCP_PROTOCOL_VERSION);
    toolContract.put("tools", toolRegistry.listTools());
    this.toolContractJson = JsonUtil.toJson(toolContract);
    this.server = createServer(config);
    this.executor = Executors.newVirtualThreadPerTaskExecutor();
    this.sseSessionSlots = new Semaphore(maxSseSessions);
    this.sseKeepaliveMillis = sseKeepaliveMillis;
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
    @SuppressWarnings("PMD.AvoidCatchingGenericException")
    public void handle(HttpExchange exchange) throws IOException {
      RequestLog log = new RequestLog(requestLogSink);
      try (exchange) {
        try {
          if (!isAllowedHost(exchange)) {
            log.method(exchange.getRequestMethod()).error().status(403);
            writePlain(exchange, 403, "Forbidden host");
            return;
          }
          if (!isAllowedOrigin(exchange)) {
            log.method(exchange.getRequestMethod()).error().status(403);
            writePlain(exchange, 403, "Forbidden origin");
            return;
          }
          addCommonHeaders(exchange);

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
            if (opensLegacySse(exchange)) {
              handleSseGet(exchange, log);
              return;
            }
            exchange.getResponseHeaders().set("Allow", "POST, GET, HEAD, OPTIONS");
            log.method(HTTP_GET_METHOD).error().status(405);
            writeJsonRpcError(
                exchange,
                405,
                null,
                JSONRPC_INVALID_REQUEST,
                "GET requires legacy SSE Accept: text/event-stream without modern MCP headers");
            return;
          }

          if (!HTTP_POST_METHOD.equalsIgnoreCase(requestMethod)) {
            exchange.getResponseHeaders().set("Allow", "POST, GET, HEAD, OPTIONS");
            log.method(requestMethod).error().status(405);
            writeJsonRpcError(
                exchange,
                405,
                null,
                JSONRPC_INVALID_REQUEST,
                "Only POST, GET (SSE), HEAD, and OPTIONS are supported for this MCP endpoint");
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

          if (!isJsonContentType(exchange)) {
            log.method(HTTP_POST_METHOD).error().status(415);
            writeJsonRpcError(
                exchange,
                415,
                null,
                JSONRPC_INVALID_REQUEST,
                "Content-Type must be application/json");
            return;
          }
          String requestBody;
          try {
            requestBody = readBody(exchange);
          } catch (PayloadTooLargeException tooLarge) {
            exchange.getResponseHeaders().set("Connection", "close");
            log.method(HTTP_POST_METHOD).error().status(413);
            writeJsonRpcError(
                exchange,
                413,
                null,
                JSONRPC_INVALID_REQUEST,
                "Request body exceeds 4 MiB limit");
            return;
          }
          Map<String, Object> request = parseRequest(requestBody);
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
            exchange.sendResponseHeaders(202, -1);
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
      if (!sseSessionSlots.tryAcquire()) {
        log.method(HTTP_GET_METHOD).error().status(503);
        writeJsonRpcError(
            exchange, 503, null, JSONRPC_INTERNAL_ERROR, "Too many active SSE sessions");
        return;
      }
      String sessionId = UUID.randomUUID().toString();
      SseSession session;
      try {
        session = new SseSession(sessionId, exchange);
      } catch (IOException error) {
        sseSessionSlots.release();
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
            if (session.awaitClose(sseKeepaliveMillis)) {
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
        session.close();
        sseSessionSlots.release();
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

  @SuppressWarnings("PMD.AvoidCatchingGenericException")
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

  private Map<String, Object> toolResult(Object result, boolean isError, boolean statelessProtocol) {
    Map<String, Object> content = new LinkedHashMap<>();
    content.put("type", "text");
    content.put("text", result instanceof String string ? string : JsonUtil.toJson(result));

    Map<String, Object> response = new LinkedHashMap<>();
    if (statelessProtocol) {
      response.put("resultType", "complete");
    }
    response.put("content", List.of(content));
    response.put("structuredContent", structuredContent(result));
    response.put("isError", isError);
    return response;
  }

  private Object structuredContent(Object result) {
    if (result instanceof Map<?, ?>) {
      return result;
    }
    Map<String, Object> wrapper = new LinkedHashMap<>();
    wrapper.put("value", result);
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

  private static String readBody(HttpExchange exchange)
      throws IOException, PayloadTooLargeException {
    String contentLengthHeader = singleHeader(exchange, "Content-Length");
    try (InputStream input = exchange.getRequestBody()) {
      if (contentLengthHeader != null) {
        try {
          long declaredLength = Long.parseLong(contentLengthHeader.trim());
          if (declaredLength > MAX_REQUEST_BODY_BYTES) {
            drainBounded(input, 0L);
            throw new PayloadTooLargeException();
          }
        } catch (NumberFormatException ignored) {
          // Defer to stream byte counter.
        }
      }
      ByteArrayOutputStream buffer = new ByteArrayOutputStream();
      byte[] chunk = new byte[READ_CHUNK_BYTES];
      long totalRead = 0L;
      while (true) {
        int read = input.read(chunk);
        if (read < 0) {
          break;
        }
        totalRead += read;
        if (totalRead > MAX_REQUEST_BODY_BYTES) {
          buffer = null;
          drainBounded(input, totalRead);
          throw new PayloadTooLargeException();
        }
        buffer.write(chunk, 0, read);
      }
      return buffer.toString(StandardCharsets.UTF_8);
    }
  }

  private static void drainBounded(InputStream input, long alreadyRead) {
    byte[] scratch = new byte[READ_CHUNK_BYTES];
    long total = alreadyRead;
    try {
      while (total < BODY_DRAIN_LIMIT_BYTES) {
        int read = input.read(scratch);
        if (read < 0) {
          break;
        }
        total += read;
      }
    } catch (IOException ignored) {
      // Best-effort bounded drain to avoid premature TCP RST on HTTP 413.
    }
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
    exchange.sendResponseHeaders(statusCode, bytes.length);
    try (OutputStream output = exchange.getResponseBody()) {
      output.write(bytes);
    }
  }

  private static void sendNoBody(HttpExchange exchange, int statusCode) throws IOException {
    exchange.sendResponseHeaders(statusCode, -1);
  }

  private void addCommonHeaders(HttpExchange exchange) {
    String origin = singleHeader(exchange, "Origin");
    if (origin != null && !origin.isBlank()) {
      exchange.getResponseHeaders().set("Access-Control-Allow-Origin", origin.trim());
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

  private boolean isAllowedHost(HttpExchange exchange) {
    InetSocketAddress localAddress = exchange.getLocalAddress();
    InetAddress localInet = localAddress == null ? null : localAddress.getAddress();
    return NetworkBinding.isAllowedHost(
        exchange.getRequestHeaders().get("Host"),
        config.host(),
        server.getAddress().getPort(),
        localInet);
  }

  private boolean isAllowedOrigin(HttpExchange exchange) {
    return NetworkBinding.isAllowedOrigin(
        exchange.getRequestHeaders().get("Origin"), config.host());
  }

  private static boolean isJsonContentType(HttpExchange exchange) {
    return isJsonContentType(singleHeader(exchange, "Content-Type"));
  }

  static boolean isJsonContentType(String contentType) {
    if (contentType == null) {
      return false;
    }
    int semicolon = contentType.indexOf(';');
    String mediaType =
        trimHttpOws(semicolon >= 0 ? contentType.substring(0, semicolon) : contentType);
    if (!"application/json".equalsIgnoreCase(mediaType)) {
      return false;
    }
    return semicolon < 0 || hasValidMediaTypeParameters(contentType, semicolon);
  }

  private static boolean hasValidMediaTypeParameters(String header, int firstSemicolon) {
    int index = firstSemicolon;
    int length = header.length();
    while (index < length) {
      if (header.charAt(index) != ';') {
        return false;
      }
      index = skipHttpOws(header, index + 1);
      if (index >= length) {
        return false;
      }
      int nameStart = index;
      while (index < length && isHttpTokenChar(header.charAt(index))) {
        index++;
      }
      if (index == nameStart || index >= length || header.charAt(index) != '=') {
        return false;
      }
      index++;
      if (index >= length) {
        return false;
      }
      if (header.charAt(index) == '"') {
        index++;
        boolean escaped = false;
        boolean closedQuote = false;
        while (index < length) {
          char ch = header.charAt(index++);
          if (escaped) {
            escaped = false;
          } else if (ch == '\\') {
            escaped = true;
          } else if (ch == '"') {
            closedQuote = true;
            break;
          }
        }
        if (!closedQuote) {
          return false;
        }
      } else {
        int valueStart = index;
        while (index < length && isHttpTokenChar(header.charAt(index))) {
          index++;
        }
        if (index == valueStart) {
          return false;
        }
      }
      index = skipHttpOws(header, index);
    }
    return true;
  }

  private static String trimHttpOws(String value) {
    int start = skipHttpOws(value, 0);
    int end = value.length();
    while (end > start && isHttpOws(value.charAt(end - 1))) {
      end--;
    }
    return value.substring(start, end);
  }

  private static int skipHttpOws(String value, int index) {
    int pos = index;
    while (pos < value.length() && isHttpOws(value.charAt(pos))) {
      pos++;
    }
    return pos;
  }

  private static boolean isHttpOws(char ch) {
    return ch == ' ' || ch == '\t';
  }

  private static boolean isHttpTokenChar(char ch) {
    return (ch >= '0' && ch <= '9')
        || (ch >= 'A' && ch <= 'Z')
        || (ch >= 'a' && ch <= 'z')
        || "!#$%&'*+-.^_`|~".indexOf(ch) >= 0;
  }

  private static boolean opensLegacySse(HttpExchange exchange) {
    var headers = exchange.getRequestHeaders();
    if (headers.containsKey("MCP-Protocol-Version")
        || headers.containsKey("Mcp-Session-Id")
        || headers.containsKey("Last-Event-Id")) {
      return false;
    }
    List<String> acceptValues = headers.get("Accept");
    if (acceptValues == null || acceptValues.isEmpty()) {
      return false;
    }
    for (String acceptValue : acceptValues) {
      if (acceptValue != null && acceptsEventStream(acceptValue)) {
        return true;
      }
    }
    return false;
  }

  static boolean acceptsEventStream(String acceptHeader) {
    for (String range : acceptHeader.split(",")) {
      String[] parts = range.split(";", -1);
      if (parts.length == 0
          || !"text/event-stream".equalsIgnoreCase(parts[0].trim())) {
        continue;
      }
      boolean validWeight = true;
      for (int i = 1; i < parts.length; i++) {
        String parameter = parts[i].trim();
        int eq = parameter.indexOf('=');
        if (eq < 0) {
          continue;
        }
        String name = parameter.substring(0, eq).trim();
        String value = parameter.substring(eq + 1).trim();
        if ("q".equalsIgnoreCase(name) && !isPositiveQuality(value)) {
          validWeight = false;
          break;
        }
      }
      if (validWeight) {
        return true;
      }
    }
    return false;
  }

  private static boolean isPositiveQuality(String value) {
    if (value.isEmpty()) {
      return false;
    }
    try {
      double quality = Double.parseDouble(value);
      return Double.isFinite(quality) && quality > 0.0 && quality <= 1.0;
    } catch (NumberFormatException invalid) {
      return false;
    }
  }

  private static String firstHeader(HttpExchange exchange, String name) {
    List<String> values = exchange.getRequestHeaders().get(name);
    return values == null || values.isEmpty() ? null : values.get(0);
  }

  private static String singleHeader(HttpExchange exchange, String name) {
    List<String> values = exchange.getRequestHeaders().get(name);
    return values == null || values.size() != 1 ? null : values.get(0);
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

  private static final class JsonRpcError extends RuntimeException {
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

  private static final class PayloadTooLargeException extends Exception {
    private static final long serialVersionUID = 1L;
  }

  static final class SseSession implements AutoCloseable {
    private final String id;
    private final HttpExchange exchange;
    private final OutputStream output;
    private final AtomicBoolean active = new AtomicBoolean(true);
    private final CountDownLatch closedLatch = new CountDownLatch(1);

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

    synchronized void sendEvent(String event, String data) throws IOException {
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
    }

    synchronized void sendComment(String comment) throws IOException {
      if (!active.get()) {
        return;
      }
      String payload = ": " + comment + "\n\n";
      output.write(payload.getBytes(StandardCharsets.UTF_8));
      output.flush();
    }

    boolean awaitClose(long timeoutMillis) throws InterruptedException {
      return closedLatch.await(timeoutMillis, TimeUnit.MILLISECONDS);
    }

    @Override
    public synchronized void close() {
      if (active.compareAndSet(true, false)) {
        closedLatch.countDown();
        try {
          output.close();
        } catch (IOException ignored) {}
        try {
          exchange.close();
        } catch (Exception ignored) {}
      }
    }

    boolean isActive() {
      return active.get();
    }
  }
}
