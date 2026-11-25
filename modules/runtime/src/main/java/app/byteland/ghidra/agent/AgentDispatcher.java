package app.byteland.ghidra.agent;

import app.byteland.ghidra.api.ApiCatalog;
import app.byteland.ghidra.api.ApiException;
import app.byteland.ghidra.api.ApiRegistry;
import app.byteland.ghidra.service.BridgeServices;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Dispatches API requests to the registry one at a time and blocks new requests during shutdown.
 */
public final class AgentDispatcher implements AutoCloseable {
  private final String sessionId;
  private final String programName;
  private final BridgeServices services;
  private final ApiRegistry apiRegistry;
  private final DispatchBarrier dispatchBarrier = new DispatchBarrier();
  private final Object sequenceLock = new Object();
  private volatile boolean shuttingDown;

  /**
   * Creates a dispatcher using the session ID from {@code config}.
   *
   * @param services domain service bundle for the open program
   * @param config runtime session configuration
   */
  public AgentDispatcher(BridgeServices services, AgentConfig config) {
    this(
        Objects.requireNonNull(services, "services"),
        Objects.requireNonNull(config, "config").sessionId());
  }

  /**
   * Creates a dispatcher for the given services and session ID.
   *
   * @param services domain service bundle for the open program
   * @param sessionId non-blank session identifier
   */
  public AgentDispatcher(BridgeServices services, String sessionId) {
    this.services = Objects.requireNonNull(services, "services");
    String normalizedSessionId = AgentConfig.optionalText(sessionId);
    if (normalizedSessionId == null) {
      throw new IllegalArgumentException("sessionId is required");
    }
    this.sessionId = normalizedSessionId;
    this.programName = services.programName();
    this.apiRegistry =
        new ApiRegistry(services, this.sessionId, this::sessionInfo, this::markShuttingDown);
  }

  @Override
  public void close() {
    if (!dispatchBarrier.closeAndAwait()) return;
    services.close();
  }

  /**
   * Dispatches a single wire method call sequentially while the session is open.
   *
   * @param method wire method name
   * @param params decoded request parameter map, or {@code null}
   * @return serialized-ready result value returned by the handler
   * @throws Exception if validation or method execution fails
   */
  public Object dispatch(String method, Map<String, Object> params) throws Exception {
    return dispatchBarrier.run(
        () -> {
          if (method == null || method.isBlank()) {
            throw ApiException.badRequest("missing_method", "method is required", "/method");
          }
          synchronized (sequenceLock) {
            return apiRegistry.dispatch(method, params);
          }
        });
  }

  /**
   * Returns the wire API method catalog exposed by this dispatcher.
   *
   * @return API method catalog
   */
  public ApiCatalog methodCatalog() {
    return apiRegistry.methodCatalog();
  }

  /**
   * Returns whether a {@code session.close} request has initiated shutdown.
   *
   * @return {@code true} if shutdown has been requested
   */
  public boolean isShuttingDown() {
    return shuttingDown;
  }

  /**
   * Returns the name of the bound Ghidra program.
   *
   * @return program name
   */
  public String getProgramName() {
    return programName;
  }

  private Map<String, Object> sessionInfo() {
    Map<String, Object> info = new LinkedHashMap<>();
    info.put("id", sessionId);
    info.put("status", shuttingDown ? "shutting_down" : "active");
    info.put("program_name", programName);
    return info;
  }

  private void markShuttingDown() {
    shuttingDown = true;
  }
}
