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
import app.byteland.ghidra.service.function.FunctionResource;
import app.byteland.ghidra.service.function.FunctionService;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService;
import app.byteland.ghidra.service.listing.ListingService;
import app.byteland.ghidra.service.memory.MemoryService;
import app.byteland.ghidra.service.program.ProgramService;
import app.byteland.ghidra.service.reference.ReferenceService;
import app.byteland.ghidra.service.symbol.SymbolService;
import java.lang.reflect.Proxy;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class FunctionMutationTest {
  @Test
  void mutationsValidateInputAndRunInTransactions() throws Exception {
    AtomicReference<List<Object>> arguments = new AtomicReference<>();
    AtomicInteger transactions = new AtomicInteger();
    FunctionService functions = proxy(FunctionService.class, (method, args) -> {
      arguments.set(Arrays.asList(args));
      if (method.equals("deleteFunction")) return null;
      assertEquals("createFunction", method);
      return new FunctionResource(
          "ram:00100000", "test_function", null, null, null, null, null, 0, null,
          null, null, null, false, false, false, false, null, false, false, null, null);
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
        functions, unused(GlobalVariableService.class), analysis,
        unused(DecompilationService.class),
        unused(SymbolService.class), unused(DataTypeService.class), transaction, "test");
    ApiRegistry registry = new ApiRegistry(services, "test", Map::of, () -> {});

    Object result = registry.dispatch("function.create", Map.of(
        "resource", Map.of("entry", "0x100000", "name", "test_function"),
        "disassemble", true));
    assertEquals(List.of("0x100000", "test_function", true), arguments.get());
    assertEquals("ram:00100000", ((Map<?, ?>) result).get("entry"));
    assertEquals(1, transactions.get());
    assertTrue(registry.method("function.create").effects().requiresTransaction());
    assertFalse(registry.method("function.create").effects().idempotent());

    registry.dispatch("function.create", Map.of("resource", Map.of("entry", "0x100000")));
    assertEquals(Arrays.asList("0x100000", null, false), arguments.get());
    assertThrows(ApiException.class, () -> registry.dispatch("function.create", Map.of(
        "resource", Map.of("name", "missing_entry"))));
    assertThrows(ApiException.class, () -> registry.dispatch("function.create", Map.of(
        "resource", Map.of("entry", "0x100000"), "disassemble", "yes")));
    assertEquals(2, transactions.get());

    Object deleted = registry.dispatch("function.delete", Map.of(
        "selector", Map.of("entry", "0x100000")));
    assertEquals(List.of("0x100000"), arguments.get());
    assertEquals(Map.of("deleted", true), deleted);
    assertTrue(registry.method("function.delete").effects().requiresTransaction());
    assertTrue(registry.method("function.delete").effects().destructive());
    assertThrows(ApiException.class, () -> registry.dispatch("function.delete", Map.of(
        "selector", Map.of("address", "0x100000"))));
    assertEquals(3, transactions.get());
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
