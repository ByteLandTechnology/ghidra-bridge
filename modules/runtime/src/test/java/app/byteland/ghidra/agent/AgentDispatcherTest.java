package app.byteland.ghidra.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.TransactionRunner;
import app.byteland.ghidra.service.address.AddressService;
import app.byteland.ghidra.service.analysis.AnalysisService;
import app.byteland.ghidra.service.comment.CommentService;
import app.byteland.ghidra.service.datatype.DataTypeService;
import app.byteland.ghidra.service.decompilation.DecompilationService;
import app.byteland.ghidra.service.function.FunctionService;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService;
import app.byteland.ghidra.service.listing.ListingService;
import app.byteland.ghidra.service.memory.MemoryService;
import app.byteland.ghidra.service.program.ProgramService;
import app.byteland.ghidra.service.reference.ReferenceService;
import app.byteland.ghidra.service.symbol.SymbolService;
import java.lang.reflect.Proxy;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class AgentDispatcherTest {

  @Test
  @DisplayName("Initializes session ID directly without AgentConfig and reports it in session.get")
  void initializesSessionIdDirectly() throws Exception {
    AtomicInteger closeCount = new AtomicInteger();
    BridgeServices services = stubServices("sample.elf", closeCount);

    try (AgentDispatcher dispatcher = new AgentDispatcher(services, "  mcp-session-42  ")) {
      assertEquals("sample.elf", dispatcher.getProgramName());
      assertFalse(dispatcher.isShuttingDown());

      @SuppressWarnings("unchecked")
      Map<String, Object> activeInfo =
          (Map<String, Object>) dispatcher.dispatch("session.get", Map.of());
      assertEquals("mcp-session-42", activeInfo.get("id"));
      assertEquals("active", activeInfo.get("status"));
      assertEquals("sample.elf", activeInfo.get("program_name"));

      dispatcher.dispatch("session.shutdown", Map.of());
      assertTrue(dispatcher.isShuttingDown());

      @SuppressWarnings("unchecked")
      Map<String, Object> shuttingDownInfo =
          (Map<String, Object>) dispatcher.dispatch("session.get", Map.of());
      assertEquals("mcp-session-42", shuttingDownInfo.get("id"));
      assertEquals("shutting_down", shuttingDownInfo.get("status"));
      assertEquals("sample.elf", shuttingDownInfo.get("program_name"));
    }

    assertEquals(2, closeCount.get());
  }

  @Test
  @DisplayName("Delegates AgentConfig constructor to sessionId constructor")
  void delegatesAgentConfigConstructor() throws Exception {
    BridgeServices services = stubServices("ws-target.bin", new AtomicInteger());
    AgentConfig serverConfig =
        AgentConfig.fromMap(
            Map.of(
                "host",
                "127.0.0.1",
                "port",
                "8765",
                "session_id",
                "ws-server-session",
                "token",
                "server-token"));

    try (AgentDispatcher dispatcher = new AgentDispatcher(services, serverConfig)) {
      @SuppressWarnings("unchecked")
      Map<String, Object> info =
          (Map<String, Object>) dispatcher.dispatch("session.get", Map.of());
      assertEquals("ws-server-session", info.get("id"));
      assertEquals("active", info.get("status"));
      assertEquals("ws-target.bin", info.get("program_name"));
    }

    AgentConfig outboundConfig =
        AgentConfig.fromMap(
            Map.of("ws_url", "ws://127.0.0.1:8765/ws/agent", "session_id", "ws-outbound-session"));

    try (AgentDispatcher dispatcher = new AgentDispatcher(services, outboundConfig)) {
      @SuppressWarnings("unchecked")
      Map<String, Object> info =
          (Map<String, Object>) dispatcher.dispatch("session.get", Map.of());
      assertEquals("ws-outbound-session", info.get("id"));
    }
  }

  @Test
  @DisplayName("Rejects null or blank sessionId and null constructor arguments")
  void rejectsInvalidConstructorInputs() {
    BridgeServices services = stubServices("sample.elf", new AtomicInteger());
    AgentConfig validConfig =
        AgentConfig.fromMap(
            Map.of(
                "host", "127.0.0.1", "port", "8765", "session_id", "demo", "token", "test-token"));

    assertThrows(
        IllegalArgumentException.class, () -> new AgentDispatcher(services, (String) null));
    assertThrows(IllegalArgumentException.class, () -> new AgentDispatcher(services, ""));
    assertThrows(IllegalArgumentException.class, () -> new AgentDispatcher(services, "   \t\n "));
    assertThrows(NullPointerException.class, () -> new AgentDispatcher(null, "demo"));
    assertThrows(
        NullPointerException.class, () -> new AgentDispatcher(services, (AgentConfig) null));
    assertThrows(NullPointerException.class, () -> new AgentDispatcher(null, validConfig));
  }

  @Test
  @DisplayName("Rejects dispatch after close")
  void rejectsDispatchAfterClose() {
    BridgeServices services = stubServices("sample.elf", new AtomicInteger());
    AgentDispatcher dispatcher = new AgentDispatcher(services, "closed-session");
    dispatcher.close();

    assertThrows(IllegalStateException.class, () -> dispatcher.dispatch("session.get", Map.of()));
  }

  private static BridgeServices stubServices(String programName, AtomicInteger closeCount) {
    AnalysisService analysis =
        closeableStub(AnalysisService.class, closeCount);
    DecompilationService decompilation =
        closeableStub(DecompilationService.class, closeCount);
    TransactionRunner transactionRunner =
        new TransactionRunner() {
          @Override
          public <T> T run(Operation<T> operation) {
            throw new AssertionError("Unexpected transaction");
          }
        };
    return new BridgeServices(
        unused(ProgramService.class),
        unused(AddressService.class),
        unused(CommentService.class),
        unused(ReferenceService.class),
        unused(MemoryService.class),
        unused(ListingService.class),
        unused(FunctionService.class),
        unused(GlobalVariableService.class),
        analysis,
        decompilation,
        unused(SymbolService.class),
        unused(DataTypeService.class),
        transactionRunner,
        programName);
  }

  private static <T> T closeableStub(Class<T> type, AtomicInteger closeCount) {
    return type.cast(
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (proxy, method, args) -> {
              if ("close".equals(method.getName())) {
                closeCount.incrementAndGet();
                return null;
              }
              throw new AssertionError("Unexpected call: " + method.getName());
            }));
  }

  private static <T> T unused(Class<T> type) {
    return type.cast(
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (proxy, method, args) -> {
              throw new AssertionError("Unexpected call: " + method.getName());
            }));
  }
}
