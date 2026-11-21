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
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.BindException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.Semaphore;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;

/**
 * HTTP server that exposes the bridge API as grouped MCP tools through Streamable HTTP and SSE.
 */
public final class McpHttpServer implements AutoCloseable {
  static final int MAX_CONCURRENT_REQUESTS = 32;
  static final int MAX_SSE_SESSIONS = 4;
  static final Duration DEFAULT_BODY_READ_TIMEOUT = Duration.ofSeconds(10);
  static final Duration DEFAULT_SSE_KEEPALIVE_INTERVAL = Duration.ofSeconds(15);
  private static final int MAX_BODY_READER_THREADS = 8;
  private static final int LISTEN_BACKLOG = 256;

  private static final int JSONRPC_PARSE_ERROR = -32700;
  private static final int JSONRPC_INVALID_REQUEST = -32600;
  private static final int JSONRPC_METHOD_NOT_FOUND = -32601;
  private static final int JSONRPC_INVALID_PARAMS = -32602;
  private static final int JSONRPC_INTERNAL_ERROR = -32603;
  private static final int JSONRPC_SERVER_BUSY = -32000;
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
  private static final String EVENT_STREAM_MEDIA_TYPE = "text/event-stream";
  private static final int BODY_READ_IN_PROGRESS = 0;
  private static final int BODY_READ_COMPLETED = 1;
  private static final int BODY_READ_TIMED_OUT = 2;

  private final McpConfig config;
  private final AgentDispatcher dispatcher;
  private final Consumer<String> requestLogSink;
  private final McpToolRegistry toolRegistry;
  private final String toolContractJson;
  private final HttpServer server;
  private final ExecutorService executor;
  private final ExecutorService bodyReaderExecutor;
  private final ScheduledExecutorService readTimeoutScheduler;
  private final long bodyReadTimeoutMillis;
  private final long sseKeepaliveMillis;
  private final Semaphore requestPermits = new Semaphore(MAX_CONCURRENT_REQUESTS);
  private final Semaphore sseSessionPermits = new Semaphore(MAX_SSE_SESSIONS);
  private final CountDownLatch shutdownLatch = new CountDownLatch(1);
  private final AtomicBoolean closed = new AtomicBoolean(false);
  private final ConcurrentHashMap<String, SseSession> sseSessions = new ConcurrentHashMap<>();

  public McpHttpServer(McpConfig config, AgentDispatcher dispatcher) throws IOException {
    this(config, dispatcher, McpHttpServer::discardRequestLog);
  }

  public McpHttpServer(
      McpConfig config, AgentDispatcher dispatcher, Consumer<String> requestLogSink)
      throws IOException {
    this(
        config,
        dispatcher,
        requestLogSink,
        DEFAULT_BODY_READ_TIMEOUT,
        DEFAULT_SSE_KEEPALIVE_INTERVAL);
  }

  McpHttpServer(
      McpConfig config,
      AgentDispatcher dispatcher,
      Consumer<String> requestLogSink,
      Duration bodyReadTimeout,
      Duration sseKeepaliveInterval)
      throws IOException {
    this.config = Objects.requireNonNull(config, "config");
    this.dispatcher = Objects.requireNonNull(dispatcher, "dispatcher");
    this.requestLogSink = Objects.requireNonNull(requestLogSink, "requestLogSink");
    Objects.requireNonNull(bodyReadTimeout, "bodyReadTimeout");
    Objects.requireNonNull(sseKeepaliveInterval, "sseKeepaliveInterval");
    if (bodyReadTimeout.isZero() || bodyReadTimeout.isNegative()) {
      throw new IllegalArgumentException("bodyReadTimeout must be positive");
    }
    if (sseKeepaliveInterval.isZero() || sseKeepaliveInterval.isNegative()) {
      throw new IllegalArgumentException("sseKeepaliveInterval must be positive");
    }
    this.bodyReadTimeoutMillis = Math.max(1L, bodyReadTimeout.toMillis());
    this.sseKeepaliveMillis = Math.max(1L, sseKeepaliveInterval.toMillis());
    this.toolRegistry = new McpToolRegistry(dispatcher.methodCatalog(), config.toolPrefix());
    Map<String, Object> toolContract = new LinkedHashMap<>();
    toolContract.put("protocol_version", MCP_PROTOCOL_VERSION);
    toolContract.put("tools", toolRegistry.listTools());
    this.toolContractJson = JsonUtil.toJson(toolContract);
    this.server = createServer(config);
    this.executor = Executors.newVirtualThreadPerTaskExecutor();
    this.bodyReaderExecutor = createBodyReaderExecutor();
    this.readTimeoutScheduler = createReadTimeoutScheduler();
    this.server.setExecutor(executor);
    this.server.createContext(config.path(), new JsonRpcHandler());
  }

  private static ExecutorService createBodyReaderExecutor() {
    AtomicInteger threadNumber = new AtomicInteger(1);
    ThreadPoolExecutor pool =
        new ThreadPoolExecutor(
            MAX_BODY_READER_THREADS,
            MAX_BODY_READER_THREADS,
            5L,
            TimeUnit.SECONDS,
            new LinkedBlockingQueue<>(),
            runnable -> {
              Thread thread =
                  new Thread(runnable, "ghidra-mcp-body-reader-" + threadNumber.getAndIncrement());
              thread.setDaemon(true);
              return thread;
            });
    pool.allowCoreThreadTimeOut(true);
    return pool;
  }

  private static ScheduledExecutorService createReadTimeoutScheduler() {
    ScheduledThreadPoolExecutor scheduler =
        new ScheduledThreadPoolExecutor(
            1,
            runnable -> {
              Thread thread = new Thread(runnable, "ghidra-mcp-read-timeout");
              thread.setDaemon(true);
              return thread;
            });
    scheduler.setRemoveOnCancelPolicy(true);
    scheduler.setExecuteExistingDelayedTasksAfterShutdownPolicy(false);
    return scheduler;
  }

  private static HttpServer createServer(McpConfig config) throws IOException {
    try {
      return HttpServer.create(
          new InetSocketAddress(config.host(), config.port()), LISTEN_BACKLOG);
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
    ExecutorShutdown.shutdownAndAwait(bodyReaderExecutor);
    ExecutorShutdown.shutdownAndAwait(readTimeoutScheduler);
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
    @SuppressWarnings({"PMD.AvoidCatchingGenericException", "PMD.CloseResource"})
    public void handle(HttpExchange exchange) throws IOException {
      RequestLog log = new RequestLog(requestLogSink);
      boolean requestPermitAcquired = false;
      boolean bodyRead = false;
      boolean closeExchange = true;
      try {
        addCommonHeaders(exchange);
        if (!isAllowedOrigin(exchange)) {
          log.method(exchange.getRequestMethod()).error().status(403);
          writePlainResponse(exchange, 403, "Forbidden origin", false);
          return;
        }

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
          writeJsonRpcErrorResponse(
              exchange,
              400,
              null,
              JSONRPC_INVALID_REQUEST,
              "Query-string tokens are not supported",
              false);
          return;
        }

        if (!authorize(exchange)) {
          exchange.getResponseHeaders().set("WWW-Authenticate", "Bearer");
          log.error().status(401);
          writeJsonRpcErrorResponse(
              exchange, 401, null, JSONRPC_UNAUTHORIZED, "Unauthorized", false);
          return;
        }

        if (HTTP_GET_METHOD.equalsIgnoreCase(requestMethod)) {
          if (!acceptsEventStream(exchange)) {
            exchange.getResponseHeaders().set("Allow", "POST, GET, OPTIONS");
            log.method(HTTP_GET_METHOD).error().status(405);
            writeJsonRpcErrorResponse(
                exchange,
                405,
                null,
                JSONRPC_INVALID_REQUEST,
                "GET requires Accept: text/event-stream",
                false);
            return;
          }
          handleSseGet(exchange, log);
          return;
        }

        if (!HTTP_POST_METHOD.equalsIgnoreCase(requestMethod)) {
          exchange.getResponseHeaders().set("Allow", "POST, GET, OPTIONS");
          log.method(requestMethod).error().status(405);
          writeJsonRpcErrorResponse(
              exchange,
              405,
              null,
              JSONRPC_INVALID_REQUEST,
              "Only POST and GET (SSE) are supported for this MCP endpoint",
              false);
          return;
        }

        if (!requestPermits.tryAcquire()) {
          exchange.getResponseHeaders().set("Connection", "close");
          log.method(HTTP_POST_METHOD).error().status(503);
          writeJsonRpcErrorResponse(
              exchange, 503, null, JSONRPC_SERVER_BUSY, "Too many concurrent requests", false);
          return;
        }
        requestPermitAcquired = true;

        String sessionId = getQueryParameter(exchange.getRequestURI(), SESSION_ID_PARAM);
        SseSession sseSession = null;
        if (sessionId != null) {
          sseSession = sseSessions.get(sessionId);
          if (sseSession == null || !sseSession.isActive()) {
            log.error().status(404);
            writeJsonRpcErrorResponse(
                exchange,
                404,
                null,
                JSONRPC_INVALID_REQUEST,
                "SSE session not found or expired",
                false);
            return;
          }
        }

        if (!String.valueOf(firstHeader(exchange, "Content-Type")).startsWith("application/json")) {
          throw new JsonRpcError(
              415, null, JSONRPC_INVALID_REQUEST, "Content-Type must be application/json");
        }
        String rawBody = readBody(exchange);
        bodyRead = true;
        Map<String, Object> request = parseRequest(rawBody);
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
      } catch (UnreadRequestAbortedException abortedUnread) {
        closeExchange = false;
        throw abortedUnread;
      } catch (JsonRpcError error) {
        log.error()
            .status(error.httpStatus())
            .id(error.id())
            .cause(error.httpStatus() >= 500 ? rootMessage(error) : null);
        Map<String, Object> errResponse =
            error.code() == UNSUPPORTED_PROTOCOL_VERSION
                ? mcpErrorResponse(
                    exchange,
                    error.id(),
                    error.code(),
                    error.getMessage(),
                    Map.of(
                        "requested",
                        error.requestedVersion(),
                        "supported",
                        SUPPORTED_PROTOCOL_VERSIONS))
                : mcpErrorResponse(exchange, error.id(), error.code(), error.getMessage(), null);
        String querySessionId = getQueryParameter(exchange.getRequestURI(), SESSION_ID_PARAM);
        SseSession activeSse = querySessionId == null ? null : sseSessions.get(querySessionId);
        if (activeSse != null && activeSse.isActive() && bodyRead) {
          try {
            activeSse.sendEvent("message", JsonUtil.toJson(errResponse));
          } catch (IOException ignored) {
          }
          exchange.sendResponseHeaders(202, -1);
        } else {
          try {
            writeJsonResponse(exchange, error.httpStatus(), errResponse, bodyRead);
          } catch (UnreadRequestAbortedException abortedUnread) {
            closeExchange = false;
            throw abortedUnread;
          }
        }
      } catch (BodyReadTimeoutException timeout) {
        log.method(HTTP_POST_METHOD).error().status(408).cause("Request body read timed out");
      } catch (IOException | RuntimeException error) {
        log.error().status(500).cause(rootMessage(error));
        try {
          writeJsonRpcErrorResponse(
              exchange, 500, null, JSONRPC_INTERNAL_ERROR, "Internal error", bodyRead);
        } catch (UnreadRequestAbortedException abortedUnread) {
          closeExchange = false;
          throw abortedUnread;
        } catch (IOException ignored) {
          // The connection closed before the error response could be sent.
        }
      } finally {
        if (requestPermitAcquired) {
          requestPermits.release();
        }
        log.finish();
        if (closeExchange) {
          exchange.close();
        }
      }
    }

    private void handleSseGet(HttpExchange exchange, RequestLog log) throws IOException {
      if (!sseSessionPermits.tryAcquire()) {
        exchange.getResponseHeaders().set("Connection", "close");
        log.method(HTTP_GET_METHOD).error().status(503);
        writeJsonRpcError(
            exchange, 503, null, JSONRPC_SERVER_BUSY, "Too many active SSE sessions");
        return;
      }
      try {
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
        }
      } finally {
        sseSessionPermits.release();
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

  private String readBody(HttpExchange exchange) throws IOException {
    if (closed.get()) {
      exchange.close();
      throw new IOException("MCP server is closed");
    }
    AtomicInteger readState = new AtomicInteger(BODY_READ_IN_PROGRESS);
    AtomicReference<Future<byte[]>> readFutureRef = new AtomicReference<>();
    ScheduledFuture<?> timeoutTask;
    try {
      timeoutTask =
          readTimeoutScheduler.schedule(
              () -> {
                if (readState.compareAndSet(BODY_READ_IN_PROGRESS, BODY_READ_TIMED_OUT)) {
                  exchange.close();
                  Future<byte[]> pendingRead = readFutureRef.get();
                  if (pendingRead != null) {
                    pendingRead.cancel(true);
                  }
                }
              },
              bodyReadTimeoutMillis,
              TimeUnit.MILLISECONDS);
    } catch (RejectedExecutionException rejected) {
      exchange.close();
      throw new IOException("MCP server is shutting down", rejected);
    }
    try {
      Future<byte[]> readFuture =
          bodyReaderExecutor.submit(
              () -> {
                try (InputStream input = exchange.getRequestBody()) {
                  return input.readAllBytes();
                }
              });
      readFutureRef.set(readFuture);
      if (readState.get() == BODY_READ_TIMED_OUT) {
        readFuture.cancel(true);
      }
      byte[] bodyBytes = readFuture.get();
      if (!readState.compareAndSet(BODY_READ_IN_PROGRESS, BODY_READ_COMPLETED)) {
        throw new BodyReadTimeoutException(null);
      }
      return new String(bodyBytes, StandardCharsets.UTF_8);
    } catch (RejectedExecutionException rejected) {
      exchange.close();
      throw new IOException("MCP server is shutting down", rejected);
    } catch (CancellationException cancelled) {
      throw new BodyReadTimeoutException(cancelled);
    } catch (InterruptedException interrupted) {
      Future<byte[]> pendingRead = readFutureRef.get();
      if (pendingRead != null) {
        pendingRead.cancel(true);
      }
      exchange.close();
      Thread.currentThread().interrupt();
      throw new IOException("Interrupted while reading request body", interrupted);
    } catch (ExecutionException failed) {
      Throwable cause = failed.getCause();
      if (readState.get() == BODY_READ_TIMED_OUT) {
        throw new BodyReadTimeoutException(cause);
      }
      if (cause instanceof IOException ioError) {
        throw ioError;
      }
      if (cause instanceof RuntimeException runtimeError) {
        throw runtimeError;
      }
      throw new IOException("Failed to read request body", cause);
    } finally {
      readState.compareAndSet(BODY_READ_IN_PROGRESS, BODY_READ_COMPLETED);
      timeoutTask.cancel(false);
    }
  }

  private static boolean acceptsEventStream(HttpExchange exchange) {
    List<String> values = exchange.getRequestHeaders().get("Accept");
    if (values == null) {
      return false;
    }
    for (String header : values) {
      if (header == null) {
        continue;
      }
      for (String part : header.split(",")) {
        int semicolon = part.indexOf(';');
        String mediaType = (semicolon >= 0 ? part.substring(0, semicolon) : part).trim();
        if (EVENT_STREAM_MEDIA_TYPE.equalsIgnoreCase(mediaType)
            && (semicolon < 0 || !isZeroQuality(part.substring(semicolon + 1)))) {
          return true;
        }
      }
    }
    return false;
  }

  private static boolean isZeroQuality(String parameters) {
    for (String parameter : parameters.split(";")) {
      int separator = parameter.indexOf('=');
      if (separator > 0 && "q".equalsIgnoreCase(parameter.substring(0, separator).trim())) {
        try {
          return Double.parseDouble(parameter.substring(separator + 1).trim()) == 0.0d;
        } catch (NumberFormatException ignored) {
          return false;
        }
      }
    }
    return false;
  }

  private static void writeJsonRpcError(
      HttpExchange exchange, int httpStatus, Object id, int code, String message)
      throws IOException {
    writeJson(exchange, httpStatus, mcpErrorResponse(exchange, id, code, message, null));
  }

  private static void writeJsonRpcErrorResponse(
      HttpExchange exchange,
      int httpStatus,
      Object id,
      int code,
      String message,
      boolean bodyRead)
      throws IOException {
    writeJsonResponse(
        exchange, httpStatus, mcpErrorResponse(exchange, id, code, message, null), bodyRead);
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

  private static void writeJsonResponse(
      HttpExchange exchange, int statusCode, Object payload, boolean bodyRead) throws IOException {
    if (bodyRead || !hasRequestBody(exchange)) {
      writeJson(exchange, statusCode, payload);
      return;
    }
    byte[] bytes = JsonUtil.toJson(payload).getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
    exchange.getResponseHeaders().set("Connection", "close");
    writeAndAbortUnread(exchange, statusCode, bytes);
  }

  private static void writePlainResponse(
      HttpExchange exchange, int statusCode, String payload, boolean bodyRead) throws IOException {
    if (bodyRead || !hasRequestBody(exchange)) {
      writePlain(exchange, statusCode, payload);
      return;
    }
    byte[] bytes = payload.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().set("Content-Type", "text/plain; charset=utf-8");
    exchange.getResponseHeaders().set("Connection", "close");
    writeAndAbortUnread(exchange, statusCode, bytes);
  }

  @SuppressWarnings("PMD.CloseResource")
  private static void writeAndAbortUnread(HttpExchange exchange, int statusCode, byte[] bytes)
      throws IOException {
    exchange.sendResponseHeaders(statusCode, bytes.length);
    OutputStream output = exchange.getResponseBody();
    output.write(bytes);
    output.flush();
    throw new UnreadRequestAbortedException();
  }

  private static boolean hasRequestBody(HttpExchange exchange) {
    if (firstHeader(exchange, "Transfer-Encoding") != null) {
      return true;
    }
    String contentLength = firstHeader(exchange, "Content-Length");
    if (contentLength == null) {
      return false;
    }
    try {
      return Long.parseLong(contentLength.trim()) > 0L;
    } catch (NumberFormatException invalid) {
      return true;
    }
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
    String origin = firstHeader(exchange, "Origin");
    if (origin != null && !origin.isBlank()) {
      exchange.getResponseHeaders().set("Access-Control-Allow-Origin", origin);
      exchange.getResponseHeaders().set("Vary", "Origin");
    } else {
      exchange.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
    }
    exchange.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, HEAD, OPTIONS");
    exchange
        .getResponseHeaders()
        .set("Access-Control-Allow-Headers", "Authorization, Content-Type, MCP-Protocol-Version, Mcp-Method, Mcp-Name, Accept");
    exchange
        .getResponseHeaders()
        .set("Access-Control-Expose-Headers", "MCP-Protocol-Version");
  }

  private boolean isAllowedOrigin(HttpExchange exchange) {
    String origin = firstHeader(exchange, "Origin");
    if (origin == null || origin.isBlank()) {
      return true;
    }
    try {
      URI uri = URI.create(origin);
      String host = uri.getHost();
      return host != null;
    } catch (IllegalArgumentException invalidOrigin) {
      return false;
    }
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

  private static final class BodyReadTimeoutException extends IOException {
    private static final long serialVersionUID = 1L;

    BodyReadTimeoutException(Throwable cause) {
      super("Request body read timed out", cause);
    }
  }

  private static final class UnreadRequestAbortedException extends IOException {
    private static final long serialVersionUID = 1L;

    UnreadRequestAbortedException() {
      super("Closing exchange without draining unread request body");
    }
  }

  private static final class SseSession implements AutoCloseable {
    private final String id;
    private final HttpExchange exchange;
    private final OutputStream output;
    private final AtomicBoolean active = new AtomicBoolean(true);
    private final CountDownLatch closedLatch = new CountDownLatch(1);
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
      } catch (IOException error) {
        close();
        throw error;
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
      } catch (IOException error) {
        close();
        throw error;
      } finally {
        writeLock.unlock();
      }
    }

    boolean awaitClose(long timeout, TimeUnit unit) throws InterruptedException {
      return closedLatch.await(timeout, unit);
    }

    @Override
    public void close() {
      closedLatch.countDown();
      if (active.compareAndSet(true, false)) {
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
