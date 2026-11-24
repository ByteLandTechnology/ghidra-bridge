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
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.datatype.DataTypeService;
import app.byteland.ghidra.service.decompilation.DecompilationService;
import app.byteland.ghidra.service.function.FunctionResource;
import app.byteland.ghidra.service.function.FunctionService;
import app.byteland.ghidra.service.function.VariableStorageReference;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService;
import app.byteland.ghidra.service.listing.ListingService;
import app.byteland.ghidra.service.memory.MemoryService;
import app.byteland.ghidra.service.program.ProgramService;
import app.byteland.ghidra.service.reference.ReferenceService;
import app.byteland.ghidra.service.symbol.SymbolService;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
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
          null, null, null, false, false, false, false, null, false, false, null, null, null);
    });
    AnalysisService analysis = proxy(AnalysisService.class, (method, args) ->
        new AnalysisResource(AnalysisResource.Kind.GHIDRA, AnalysisResource.Status.IDLE,
            false, null, null, null, null, null, null));
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

  @Test
  void parameterCreateDispatchesAndRunsInTransactionWithAndWithoutStorage() throws Exception {
    AtomicReference<List<Object>> addParameterArgs = new AtomicReference<>();
    AtomicBoolean inTransaction = new AtomicBoolean();
    AtomicInteger transactions = new AtomicInteger();
    List<FunctionResource.ParameterResource> storedParameters = new ArrayList<>();

    FunctionService functions = proxy(FunctionService.class, (method, args) -> {
      assertTrue(inTransaction.get(), "FunctionService call must execute inside transaction");
      if (method.equals("addParameter")) {
        addParameterArgs.set(Arrays.asList(args));
        int ordinal = (Integer) args[1];
        String name = (String) args[2];
        DataTypeReference dataType = (DataTypeReference) args[3];
        VariableStorageReference storage = (VariableStorageReference) args[4];
        VariableStorageReference resolvedStorage =
            storage == null
                ? VariableStorageReference.serialization("register:00000038:4")
                : VariableStorageReference.serialization("register:000000a0:8");
        storedParameters.add(
            ordinal, new FunctionResource.ParameterResource(ordinal, name, dataType, resolvedStorage));
        return null;
      }
      assertEquals("getFunction", method);
      assertEquals(List.of("0x100000", Set.of("parameters")), Arrays.asList(args));
      return new FunctionResource(
          "ram:00100000", "test_function", null, null, null, null, null, storedParameters.size(),
          null, storedParameters, null, null, false, false, false, false, null, false, false, null,
          null, null);
    });
    AnalysisService analysis = proxy(AnalysisService.class, (method, args) ->
        new AnalysisResource(AnalysisResource.Kind.GHIDRA, AnalysisResource.Status.IDLE,
            false, null, null, null, null));
    TransactionRunner transaction = new TransactionRunner() {
      @Override
      public <T> T run(Operation<T> operation) {
        transactions.incrementAndGet();
        inTransaction.set(true);
        try {
          return operation.execute();
        } catch (Exception ex) {
          throw new RuntimeException(ex);
        } finally {
          inTransaction.set(false);
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

    assertTrue(registry.method("function_parameter.create").effects().requiresTransaction());
    assertFalse(registry.method("function_parameter.create").effects().idempotent());
    assertFalse(registry.method("function_parameter.create").effects().destructive());

    Object dynamicCreated = registry.dispatch("function_parameter.create", Map.of(
        "selector", Map.of("entry", "0x100000"),
        "resource", Map.of(
            "ordinal", 0,
            "name", "count",
            "data_type", Map.of("kind", "named", "name", "/int"))));
    assertEquals(
        Arrays.asList("0x100000", 0, "count", DataTypeReference.named("/int"), null),
        addParameterArgs.get());
    assertEquals(
        Map.of(
            "ordinal", 0,
            "name", "count",
            "data_type", Map.of("kind", "named", "name", "/int"),
            "storage", Map.of("kind", "serialization", "serialization", "register:00000038:4")),
        dynamicCreated);
    assertEquals(1, transactions.get());

    Object customCreated = registry.dispatch("function_parameter.create", Map.of(
        "selector", Map.of("entry", "0x100000"),
        "resource", Map.of(
            "ordinal", 1,
            "name", "ctx",
            "data_type", Map.of("kind", "named", "name", "/longlong"),
            "storage", Map.of("kind", "register", "register", "R12"))));
    assertEquals(
        List.of(
            "0x100000",
            1,
            "ctx",
            DataTypeReference.named("/longlong"),
            VariableStorageReference.register("R12")),
        addParameterArgs.get());
    assertEquals(
        Map.of(
            "ordinal", 1,
            "name", "ctx",
            "data_type", Map.of("kind", "named", "name", "/longlong"),
            "storage", Map.of("kind", "serialization", "serialization", "register:000000a0:8")),
        customCreated);
    assertEquals(2, transactions.get());

    assertThrows(ApiException.class, () -> registry.dispatch("function_parameter.create", Map.of(
        "selector", Map.of("entry", "0x100000"),
        "resource", Map.of(
            "ordinal", -1,
            "name", "bad_ordinal",
            "data_type", Map.of("kind", "named", "name", "/int")))));
    assertThrows(ApiException.class, () -> registry.dispatch("function_parameter.create", Map.of(
        "selector", Map.of("entry", "0x100000"),
        "resource", Map.of(
            "ordinal", 0,
            "data_type", Map.of("kind", "named", "name", "/int")))));
    assertEquals(2, transactions.get());
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
