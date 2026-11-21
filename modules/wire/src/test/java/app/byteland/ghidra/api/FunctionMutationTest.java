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

@SuppressWarnings({
  "PMD.UnitTestAssertionsShouldIncludeMessage",
  "PMD.UnitTestContainsTooManyAsserts"
})
class FunctionMutationTest {
  private static final String FUNCTION_CREATE_METHOD = "function.create";
  private static final String FUNCTION_DELETE_METHOD = "function.delete";
  private static final String DELETE_FUNCTION_CALL = "deleteFunction";
  private static final String RESOURCE_KEY = "resource";
  private static final String ENTRY_KEY = "entry";
  private static final String ENTRY_ADDRESS = "0x100000";

  @Test
  @SuppressWarnings("PMD.CloseResource")
  void mutationsValidateInputAndRunInTransactions() throws Exception {
    AtomicReference<List<Object>> arguments = new AtomicReference<>();
    AtomicInteger transactions = new AtomicInteger();
    FunctionService functions = proxy(FunctionService.class, (method, args) -> {
      arguments.set(Arrays.asList(args));
      if (DELETE_FUNCTION_CALL.equals(method)) return null;
      assertEquals("createFunction", method);
      return new FunctionResource(
          "ram:00100000", "test_function", null, null, null, null, null, 0, null,
          null, null, null, false, false, false, false, null, false, false, null, null, null);
    });
    AnalysisService analysis = proxy(AnalysisService.class, (method, args) ->
        new AnalysisResource(AnalysisResource.Kind.GHIDRA, AnalysisResource.Status.IDLE,
            false, null, null, null, null));
    TransactionRunner transaction = new TransactionRunner() {
      @Override
      @SuppressWarnings("PMD.AvoidCatchingGenericException")
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

    Object result = registry.dispatch(FUNCTION_CREATE_METHOD, Map.of(
        RESOURCE_KEY, Map.of(ENTRY_KEY, ENTRY_ADDRESS, "name", "test_function"),
        "disassemble", true));
    assertEquals(List.of(ENTRY_ADDRESS, "test_function", true), arguments.get());
    assertEquals("ram:00100000", ((Map<?, ?>) result).get(ENTRY_KEY));
    assertEquals(1, transactions.get());
    assertTrue(registry.method(FUNCTION_CREATE_METHOD).effects().requiresTransaction());
    assertFalse(registry.method(FUNCTION_CREATE_METHOD).effects().idempotent());

    registry.dispatch(FUNCTION_CREATE_METHOD, Map.of(RESOURCE_KEY, Map.of(ENTRY_KEY, ENTRY_ADDRESS)));
    assertEquals(Arrays.asList(ENTRY_ADDRESS, null, false), arguments.get());
    assertThrows(ApiException.class, () -> registry.dispatch(FUNCTION_CREATE_METHOD, Map.of(
        RESOURCE_KEY, Map.of("name", "missing_entry"))));
    assertThrows(ApiException.class, () -> registry.dispatch(FUNCTION_CREATE_METHOD, Map.of(
        RESOURCE_KEY, Map.of(ENTRY_KEY, ENTRY_ADDRESS), "disassemble", "yes")));
    assertEquals(2, transactions.get());

    Object deleted = registry.dispatch(FUNCTION_DELETE_METHOD, Map.of(
        "selector", Map.of(ENTRY_KEY, ENTRY_ADDRESS)));
    assertEquals(List.of(ENTRY_ADDRESS), arguments.get());
    assertEquals(Map.of("deleted", true), deleted);
    assertTrue(registry.method(FUNCTION_DELETE_METHOD).effects().requiresTransaction());
    assertTrue(registry.method(FUNCTION_DELETE_METHOD).effects().destructive());
    assertThrows(ApiException.class, () -> registry.dispatch(FUNCTION_DELETE_METHOD, Map.of(
        "selector", Map.of("address", ENTRY_ADDRESS))));
    assertEquals(3, transactions.get());
  }

  @FunctionalInterface
  private interface Handler {
    Object invoke(String method, Object... args);
  }

  private static <T> T unused(Class<T> type) {
    return proxy(type, (method, args) -> { throw new AssertionError(method); });
  }

  @SuppressWarnings("PMD.UseProperClassLoader")
  private static <T> T proxy(Class<T> type, Handler handler) {
    return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] {type},
        (proxy, method, args) -> handler.invoke(method.getName(), args)));
  }
}
