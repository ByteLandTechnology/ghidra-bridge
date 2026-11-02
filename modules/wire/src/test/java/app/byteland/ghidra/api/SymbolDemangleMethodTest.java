package app.byteland.ghidra.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class SymbolDemangleMethodTest {
  @Test
  void demangleRunsInOneTransactionAndReturnsCounts() throws Exception {
    AtomicInteger transactions = new AtomicInteger();
    SymbolService symbols = proxy(SymbolService.class, (method, args) -> {
      assertEquals("demangleSymbols", method);
      return new SymbolService.DemangleResult(2, 1, List.of("_Zbad: No supported C++ name"));
    });
    AnalysisService analysis = proxy(AnalysisService.class, (method, args) ->
        new AnalysisResource(AnalysisResource.Kind.GHIDRA, AnalysisResource.Status.IDLE,
            false, null, null, null, null));
    TransactionRunner transaction = new TransactionRunner() {
      @Override
      public <T> T run(Operation<T> operation) {
        transactions.incrementAndGet();
        try {
          return operation.execute();
        } catch (Exception ex) {
          throw new RuntimeException(ex);
        }
      }
    };
    BridgeServices services = new BridgeServices(
        unused(ProgramService.class), unused(AddressService.class), unused(CommentService.class),
        unused(ReferenceService.class), unused(MemoryService.class), unused(ListingService.class),
        unused(FunctionService.class), unused(GlobalVariableService.class),
        analysis, unused(DecompilationService.class),
        symbols, unused(DataTypeService.class), transaction, "test");
    ApiRegistry registry = new ApiRegistry(services, "test", Map::of, () -> {});

    Map<?, ?> result = (Map<?, ?>) registry.dispatch("symbol.demangle", Map.of());
    assertEquals(2, result.get("renamed"));
    assertEquals(1, result.get("failed"));
    assertEquals(List.of("_Zbad: No supported C++ name"), result.get("failures"));
    assertEquals(1, transactions.get());
    assertTrue(registry.method("symbol.demangle").effects().requiresTransaction());
    assertFalse(registry.method("symbol.demangle").effects().destructive());
    assertTrue(registry.method("symbol.demangle").effects().idempotent());
    assertThrows(ApiException.class,
        () -> registry.dispatch("symbol.demangle", Map.of("unknown", true)));
  }

  private interface Handler {
    Object invoke(String method, Object[] args);
  }

  private static <T> T unused(Class<T> type) {
    return proxy(type, (method, args) -> { throw new AssertionError(method); });
  }

  private static <T> T proxy(Class<T> type, Handler handler) {
    return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] {type},
        (proxy, method, args) -> handler.invoke(method.getName(), args)));
  }
}
