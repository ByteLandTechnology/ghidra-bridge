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
  private final BridgeServices services;
  private final boolean closeServicesOnClose;
  private final ApiRegistry apiRegistry;
  private final DispatchBarrier dispatchBarrier = new DispatchBarrier();
  private final Object sequenceLock = new Object();
  private volatile boolean shuttingDown;

  public AgentDispatcher(BridgeServices services, AgentConfig config) {
    this(services, config, true);
  }

  public AgentDispatcher(
      BridgeServices services, AgentConfig config, boolean closeServicesOnClose) {
    this(
        Objects.requireNonNull(services, "services"),
        Objects.requireNonNull(config, "config").sessionId(),
        closeServicesOnClose);
  }

  public AgentDispatcher(BridgeServices services, String sessionId) {
    this(services, sessionId, true);
  }

  public AgentDispatcher(
      BridgeServices services, String sessionId, boolean closeServicesOnClose) {
    this.services = Objects.requireNonNull(services, "services");
    String normalizedSessionId = AgentConfig.optionalText(sessionId);
    if (normalizedSessionId == null) {
      throw new IllegalArgumentException("sessionId is required");
    }
    this.sessionId = normalizedSessionId;
    this.closeServicesOnClose = closeServicesOnClose;
    this.apiRegistry =
        new ApiRegistry(services, this.sessionId, this::sessionInfo, this::markShuttingDown);
  }

  @Override
  public void close() {
    if (!dispatchBarrier.closeAndAwait()) return;
    if (closeServicesOnClose) {
      services.close();
    }
  }

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

  public ApiCatalog methodCatalog() {
    return apiRegistry.methodCatalog();
  }

  public boolean isShuttingDown() {
    return shuttingDown;
  }

  public String getProgramName() {
    return services.currentProgramName();
  }

  private Map<String, Object> sessionInfo() {
    Map<String, Object> info = new LinkedHashMap<>();
    info.put("id", sessionId);
    info.put("status", shuttingDown ? "shutting_down" : "active");
    info.put("program_name", services.currentProgramName());
    return info;
  }

  private void markShuttingDown() {
    shuttingDown = true;
  }
}
