package app.byteland.ghidra.agent;

import app.byteland.ghidra.api.ApiCatalog;
import app.byteland.ghidra.api.ApiRegistry;
import app.byteland.ghidra.service.BridgeServices;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Dispatches API requests with concurrent shared reads, fair exclusive writes, and graceful
 * shutdown barriers.
 */
public final class AgentDispatcher implements AutoCloseable {
  private final String sessionId;
  private final String programName;
  private final BridgeServices services;
  private final ApiRegistry apiRegistry;
  private final DispatchBarrier dispatchBarrier = new DispatchBarrier();
  private volatile boolean shuttingDown;

  public AgentDispatcher(BridgeServices services, AgentConfig config) {
    this(
        Objects.requireNonNull(services, "services"),
        Objects.requireNonNull(config, "config").sessionId());
  }

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

  public Object dispatch(String method, Map<String, Object> params) throws Exception {
    return dispatchBarrier.run(
        () -> {
          ApiRegistry.PreparedDispatch prepared = apiRegistry.prepareDispatch(method, params);
          Object rawResponse =
              prepared.readOnly()
                  ? dispatchBarrier.runRead(prepared::execute)
                  : dispatchBarrier.runWrite(prepared::execute);
          return prepared.encodeResponse(rawResponse);
        });
  }

  /**
   * Runs a lifecycle action under the fair write lock while the dispatcher is open.
   */
  public void runExclusive(Runnable action) {
    Objects.requireNonNull(action, "action");
    try {
      dispatchBarrier.run(
          () ->
              dispatchBarrier.runWrite(
                  () -> {
                    action.run();
                    return null;
                  }));
    } catch (RuntimeException error) {
      throw error;
    } catch (Exception error) {
      throw new IllegalStateException("Exclusive dispatcher action failed", error);
    }
  }

  DispatchBarrier barrier() {
    return dispatchBarrier;
  }

  public ApiCatalog methodCatalog() {
    return apiRegistry.methodCatalog();
  }

  public boolean isShuttingDown() {
    return shuttingDown;
  }

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
