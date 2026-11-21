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
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
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

  @Test
  void patchesTemporaryLocalsAndInferredParametersWithReadbackAndErrorMapping() throws Exception {
    AtomicReference<String> localName = new AtomicReference<>("uVar1");
    AtomicReference<DataTypeReference> localType =
        new AtomicReference<>(DataTypeReference.named("undefined4"));
    AtomicReference<String> paramName = new AtomicReference<>("param_1");
    AtomicReference<DataTypeReference> paramType =
        new AtomicReference<>(DataTypeReference.named("int"));
    AtomicInteger transactions = new AtomicInteger();

    FunctionService functions = proxy(FunctionService.class, (method, args) -> switch (method) {
      case "patchLocalVariable" -> {
        String target = (String) args[1];
        String newName = (String) args[2];
        DataTypeReference newType = (DataTypeReference) args[3];
        if ("duplicate_target".equals(newName)) {
          throw new IllegalArgumentException("duplicate variable name: " + newName);
        }
        if (localName.get().equals(target)) {
          if (newName != null) localName.set(newName);
          if (newType != null) localType.set(newType);
          yield null;
        }
        if (paramName.get().equals(target)) {
          if (newName != null) paramName.set(newName);
          if (newType != null) paramType.set(newType);
          yield null;
        }
        throw new NoSuchElementException("local variable not found: " + target);
      }
      case "patchParameter" -> {
        int ordinal = (Integer) args[1];
        String newName = (String) args[2];
        DataTypeReference newType = (DataTypeReference) args[3];
        if (ordinal != 0) {
          throw new NoSuchElementException("parameter ordinal not found: " + ordinal);
        }
        if (newName != null) paramName.set(newName);
        if (newType != null) paramType.set(newType);
        yield null;
      }
      case "getFunction" -> {
        @SuppressWarnings("unchecked")
        Set<String> includes = (Set<String>) args[1];
        List<FunctionResource.ParameterResource> params = includes.contains("parameters")
            ? List.of(new FunctionResource.ParameterResource(
                0, paramName.get(), paramType.get(),
                VariableStorageReference.serialization("EDI:4")))
            : null;
        List<FunctionResource.LocalVariableResource> locals = includes.contains("locals")
            ? List.of(new FunctionResource.LocalVariableResource(
                localName.get(), localType.get(),
                VariableStorageReference.serialization("HASH:55aa:4")))
            : null;
        yield new FunctionResource(
            "ram:00101000", "compute_temp", "Global", null, null, null, null, 1, "__stdcall",
            params, locals, null, false, false, false, false, null, false, false, null, null, null);
      }
      default -> throw new AssertionError(method);
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
        } catch (RuntimeException ex) {
          throw ex;
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

    Map<?, ?> patchedTemp = (Map<?, ?>) registry.dispatch("function_local_variable.patch", Map.of(
        "selector", Map.of("entry", "0x101000", "name", "uVar1"),
        "patch", Map.of(
            "name", "masked_value",
            "data_type", Map.of("kind", "named", "name", "uint"))));
    assertEquals("masked_value", patchedTemp.get("name"));
    assertEquals(Map.of("kind", "named", "name", "uint"), patchedTemp.get("data_type"));

    Map<?, ?> patchedParamViaLocal = (Map<?, ?>) registry.dispatch(
        "function_local_variable.patch",
        Map.of(
            "selector", Map.of("entry", "0x101000", "name", "param_1"),
            "patch", Map.of(
                "name", "seed_input",
                "data_type", Map.of("kind", "named", "name", "uint"))));
    assertEquals("seed_input", patchedParamViaLocal.get("name"));
    assertEquals(Map.of("kind", "named", "name", "uint"), patchedParamViaLocal.get("data_type"));

    Map<?, ?> patchedParamByOrdinal = (Map<?, ?>) registry.dispatch(
        "function_parameter.patch",
        Map.of(
            "selector", Map.of("entry", "0x101000", "ordinal", 0),
            "patch", Map.of(
                "name", "final_input",
                "data_type", Map.of("kind", "named", "name", "int"))));
    assertEquals(0, patchedParamByOrdinal.get("ordinal"));
    assertEquals("final_input", patchedParamByOrdinal.get("name"));
    assertEquals(Map.of("kind", "named", "name", "int"), patchedParamByOrdinal.get("data_type"));
    assertEquals(3, transactions.get());

    IllegalArgumentException dupError = assertThrows(
        IllegalArgumentException.class,
        () -> registry.dispatch("function_local_variable.patch", Map.of(
            "selector", Map.of("entry", "0x101000", "name", "masked_value"),
            "patch", Map.of("name", "duplicate_target"))));
    ApiFailures.Failure badRequest = ApiFailures.normalize(dupError);
    assertEquals(400, badRequest.status());
    assertEquals("invalid_request", badRequest.error().code());

    NoSuchElementException missingError = assertThrows(
        NoSuchElementException.class,
        () -> registry.dispatch("function_local_variable.patch", Map.of(
            "selector", Map.of("entry", "0x101000", "name", "uVar_missing"),
            "patch", Map.of("name", "other"))));
    ApiFailures.Failure notFound = ApiFailures.normalize(missingError);
    assertEquals(404, notFound.status());
    assertEquals("resource_not_found", notFound.error().code());
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
