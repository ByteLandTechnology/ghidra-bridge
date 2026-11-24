package app.byteland.ghidra.agent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.api.ApiException;
import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.TransactionRunner;
import app.byteland.ghidra.service.address.AddressService;
import app.byteland.ghidra.service.analysis.AnalysisResource;
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
import org.junit.jupiter.api.Test;

class AgentDispatcherTest {
  @Test
  void requiresServicesAndNonBlankSessionId() {
    BridgeServices services = createServices("sample.elf", new AtomicInteger(), new AtomicInteger());
    assertThrows(NullPointerException.class, () -> new AgentDispatcher(null, "demo-session"));
    assertEquals(
        "session_id is required",
        assertThrows(IllegalArgumentException.class, () -> new AgentDispatcher(services, null))
            .getMessage());
    assertEquals(
        "session_id is required",
        assertThrows(IllegalArgumentException.class, () -> new AgentDispatcher(services, ""))
            .getMessage());
    assertEquals(
        "session_id is required",
        assertThrows(IllegalArgumentException.class, () -> new AgentDispatcher(services, "   \t\n "))
            .getMessage());
  }

  @Test
  void dispatchesSessionStateAndClosesServicesOnce() throws Exception {
    AtomicInteger analysisClosed = new AtomicInteger();
    AtomicInteger decompilerClosed = new AtomicInteger();
    BridgeServices services = createServices("sample.elf", analysisClosed, decompilerClosed);

    AgentDispatcher dispatcher = new AgentDispatcher(services, "  session-42  ");
    assertEquals("sample.elf", dispatcher.getProgramName());
    assertEquals(56, dispatcher.methodCatalog().methods().size());
    assertFalse(dispatcher.isShuttingDown());

    assertEquals(
        Map.of("id", "session-42", "status", "active", "program_name", "sample.elf"),
        dispatcher.dispatch("session.get", Map.of()));

    ApiException missingMethod =
        assertThrows(ApiException.class, () -> dispatcher.dispatch("  ", Map.of()));
    assertEquals(400, missingMethod.status());
    assertEquals("missing_method", missingMethod.error().code());

    assertEquals(Map.of("shutdown", true), dispatcher.dispatch("session.shutdown", Map.of()));
    assertTrue(dispatcher.isShuttingDown());
    assertEquals(
        Map.of("id", "session-42", "status", "shutting_down", "program_name", "sample.elf"),
        dispatcher.dispatch("session.get", Map.of()));

    dispatcher.close();
    dispatcher.close();
    assertEquals(1, analysisClosed.get());
    assertEquals(1, decompilerClosed.get());

    var closedError =
        assertThrows(IllegalStateException.class, () -> dispatcher.dispatch("session.get", Map.of()));
    assertEquals("Agent dispatcher is shutting down", closedError.getMessage());
  }

  private static BridgeServices createServices(
      String programName, AtomicInteger analysisClosed, AtomicInteger decompilerClosed) {
    AnalysisService analysis =
        proxy(
            AnalysisService.class,
            method -> {
              if ("close".equals(method)) {
                analysisClosed.incrementAndGet();
                return null;
              }
              return new AnalysisResource(
                  AnalysisResource.Kind.GHIDRA,
                  AnalysisResource.Status.IDLE,
                  false,
                  null,
                  null,
                  null,
                  null);
            });
    DecompilationService decompilation =
        proxy(
            DecompilationService.class,
            method -> {
              if ("close".equals(method)) {
                decompilerClosed.incrementAndGet();
                return null;
              }
              throw new AssertionError(method);
            });
    TransactionRunner transactionRunner =
        new TransactionRunner() {
          @Override
          public <T> T run(Operation<T> operation) {
            try {
              return operation.execute();
            } catch (Exception failure) {
              throw new RuntimeException(failure);
            }
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

  private interface MethodHandler {
    Object invoke(String method);
  }

  private static <T> T unused(Class<T> type) {
    return proxy(
        type,
        method -> {
          throw new AssertionError(method);
        });
  }

  private static <T> T proxy(Class<T> type, MethodHandler handler) {
    return type.cast(
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (proxy, method, args) -> {
              if (method.getDeclaringClass() == Object.class) {
                return switch (method.getName()) {
                  case "toString" -> type.getSimpleName();
                  case "hashCode" -> System.identityHashCode(proxy);
                  case "equals" -> proxy == args[0];
                  default -> null;
                };
              }
              return handler.invoke(method.getName());
            }));
  }
}
