package app.byteland.ghidra.api;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import app.byteland.ghidra.api.ApiMethod.MethodEffects;
import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.ScanProgress;
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
import app.byteland.ghidra.service.program.ProgramResource;
import app.byteland.ghidra.service.program.ProgramService;
import app.byteland.ghidra.service.reference.ReferenceService;
import app.byteland.ghidra.service.symbol.SymbolService;
import java.lang.reflect.Proxy;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class BatchQueryMethodTest {

  private static final Map<String, Map<String, Object>> READ_ONLY_BATCHABLE_SAMPLE_ARGUMENTS =
      Map.ofEntries(
          Map.entry("session.get", Map.of()),
          Map.entry("program.get", Map.of()),
          Map.entry("program_language.get", Map.of()),
          Map.entry("address_space.list", Map.of()),
          Map.entry("address.resolve", Map.of("selector", Map.of("address", "ram:00100000"))),
          Map.entry("memory_block.get", Map.of("selector", Map.of("name", ".text"))),
          Map.entry("memory_block.list", Map.of()),
          Map.entry("memory.read", Map.of("selector", Map.of("address", "ram:00100000"))),
          Map.entry("code_unit.list", Map.of()),
          Map.entry("data_unit.list", Map.of()),
          Map.entry("instruction.get", Map.of("selector", Map.of("address", "ram:00100000"))),
          Map.entry("instruction.list", Map.of()),
          Map.entry(
              "flow_override.list",
              Map.of(
                  "filter",
                  Map.of("selector", Map.of("kind", "address", "address", "ram:00100000")))),
          Map.entry("global_variable.get", Map.of("selector", Map.of("address", "ram:00100000"))),
          Map.entry("global_variable.list", Map.of()),
          Map.entry("function.get", Map.of("selector", Map.of("entry", "ram:00100000"))),
          Map.entry("function.list", Map.of()),
          Map.entry("function_call.list", Map.of("filter", Map.of("entry", "ram:00100000"))),
          Map.entry("analysis.get", Map.of()),
          Map.entry("decompilation.get", Map.of("selector", Map.of("entry", "ram:00100000"))),
          Map.entry("symbol.get", Map.of("selector", Map.of("id", "1"))),
          Map.entry("symbol.list", Map.of()),
          Map.entry(
              "reference.list",
              Map.of("filter", Map.of("direction", "to", "to", "ram:00100000"))),
          Map.entry(
              "comment.get",
              Map.of("selector", Map.of("address", "ram:00100000", "type", "eol"))),
          Map.entry("comment.list", Map.of()),
          Map.entry("data_type_category.list", Map.of()),
          Map.entry("data_type.get", Map.of("selector", Map.of("path", "/int"))),
          Map.entry("data_type.list", Map.of()));

  @Test
  @SuppressWarnings("unchecked")
  void batchQueryAcceptsAll28ReadOnlyBatchableMethodsAndRejectsAll23MutatingBatchableMethods() {
    Harness harness = new Harness();
    ApiMethod<Map<String, Object>, Object> queryMethod = harness.registry.method("batch.query");
    assertEquals(
        new MethodEffects(true, false, false, true, false, true, false), queryMethod.effects());

    Set<String> readOnlyBatchable = new LinkedHashSet<>();
    Set<String> mutatingBatchable = new LinkedHashSet<>();
    Set<String> nonBatchable = new LinkedHashSet<>();
    for (ApiMethod<Map<String, Object>, Object> method : harness.registry.methods()) {
      if (method.effects().batchable()) {
        if (method.effects().readOnly()) {
          readOnlyBatchable.add(method.name());
        } else {
          mutatingBatchable.add(method.name());
        }
      } else {
        nonBatchable.add(method.name());
      }
    }

    assertEquals(28, readOnlyBatchable.size());
    assertEquals(23, mutatingBatchable.size());
    assertEquals(6, nonBatchable.size());
    assertEquals(READ_ONLY_BATCHABLE_SAMPLE_ARGUMENTS.keySet(), readOnlyBatchable);

    Map<String, Object> properties =
        (Map<String, Object>) queryMethod.requestCodec().schema().get("properties");
    Map<String, Object> itemsSchema = (Map<String, Object>) properties.get("items");
    Map<String, Object> itemSchema = (Map<String, Object>) itemsSchema.get("items");
    List<Map<String, Object>> oneOf = (List<Map<String, Object>>) itemSchema.get("oneOf");
    assertEquals(28, oneOf.size());

    for (String methodName : readOnlyBatchable) {
      Map<String, Object> args = READ_ONLY_BATCHABLE_SAMPLE_ARGUMENTS.get(methodName);
      assertDoesNotThrow(
          () ->
              queryMethod.decodeRequest(
                  Map.of(
                      "items",
                      List.of(Map.of("id", "ok", "method", methodName, "arguments", args)))),
          methodName);
    }

    for (String methodName : mutatingBatchable) {
      harness.sessionGetCalls.set(0);
      ApiException rejected =
          assertThrows(
              ApiException.class,
              () ->
                  harness.registry.dispatch(
                      "batch.query",
                      Map.of(
                          "items",
                          List.of(
                              Map.of("id", "read-0", "method", "session.get", "arguments", Map.of()),
                              Map.of("id", "mut-1", "method", methodName, "arguments", Map.of())))),
              methodName);
      assertEquals(400, rejected.status());
      assertEquals("validation_failed", rejected.error().code());
      assertEquals("/items", rejected.error().target());
      assertEquals(0, harness.sessionGetCalls.get(), "prevalidation must run before any item");
      List<Map<String, Object>> violations =
          (List<Map<String, Object>>) rejected.error().details().get("violations");
      assertEquals(1, violations.size());
      assertEquals("/items/1/method", violations.getFirst().get("target"));
      assertEquals("invalid_method", violations.getFirst().get("code"));
    }

    for (String methodName : nonBatchable) {
      ApiException rejected =
          assertThrows(
              ApiException.class,
              () ->
                  harness.registry.dispatch(
                      "batch.query",
                      Map.of(
                          "items",
                          List.of(Map.of("id", "nb-0", "method", methodName, "arguments", Map.of())))),
              methodName);
      assertEquals(400, rejected.status());
      assertEquals("validation_failed", rejected.error().code());
    }
  }

  @Test
  @SuppressWarnings("unchecked")
  void batchQueryRunsWhileAnalysisIsActiveWithoutStartingTransactions() throws Exception {
    Harness harness = new Harness();
    harness.analysisRunning.set(true);

    Map<String, Object> result =
        (Map<String, Object>)
            harness.registry.dispatch(
                "batch.query",
                Map.of(
                    "transaction_mode",
                    "per_item",
                    "items",
                    List.of(
                        Map.of("id", "s1", "method", "session.get", "arguments", Map.of()),
                        Map.of("id", "p1", "method", "program.get", "arguments", Map.of()),
                        Map.of(
                            "id",
                            "fn1",
                            "method",
                            "function.list",
                            "arguments",
                            Map.of("page", Map.of("limit", 10))))));

    List<Map<String, Object>> rows = (List<Map<String, Object>>) result.get("items");
    assertEquals(3, rows.size());
    assertEquals("s1", rows.get(0).get("id"));
    assertEquals("p1", rows.get(1).get("id"));
    assertEquals("fn1", rows.get(2).get("id"));
    assertFalse(rows.get(0).containsKey("error"));
    assertFalse(rows.get(1).containsKey("error"));
    assertFalse(rows.get(2).containsKey("error"));
    assertEquals(1, harness.sessionGetCalls.get());

    harness.sessionGetCalls.set(0);
    ApiException stopped =
        assertThrows(
            ApiException.class,
            () ->
                harness.registry.dispatch(
                    "batch.query",
                    Map.of(
                        "transaction_mode",
                        "all_or_none",
                        "items",
                        List.of(
                            Map.of("id", "s1", "method", "session.get", "arguments", Map.of()),
                            Map.of(
                                "id",
                                "bad-addr",
                                "method",
                                "address.resolve",
                                "arguments",
                                Map.of("selector", Map.of("address", "ram:00100000"))),
                            Map.of("id", "s2", "method", "session.get", "arguments", Map.of())))));
    assertEquals(409, stopped.status());
    assertEquals("batch_rolled_back", stopped.error().code());
    assertEquals("bad-addr", stopped.error().details().get("failed_item"));
    assertEquals(1, harness.sessionGetCalls.get());
  }

  private static final class Harness {
    final AtomicBoolean analysisRunning = new AtomicBoolean(false);
    final AtomicInteger sessionGetCalls = new AtomicInteger();
    final ApiRegistry registry;

    Harness() {
      AnalysisService analysis =
          proxy(
              AnalysisService.class,
              (method, args) ->
                  new AnalysisResource(
                      AnalysisResource.Kind.GHIDRA,
                      analysisRunning.get()
                          ? AnalysisResource.Status.RUNNING
                          : AnalysisResource.Status.IDLE,
                      analysisRunning.get(),
                      null,
                      null,
                      null,
                      null));
      ProgramService program =
          proxy(
              ProgramService.class,
              (method, args) ->
                  new ProgramResource(
                      "sample.bin",
                      "/bin/sample.bin",
                      "ELF",
                      "ram:00100000",
                      "ram:00100000",
                      "ram:0010ffff",
                      "x86:LE:64:default",
                      "gcc",
                      Instant.EPOCH,
                      Instant.EPOCH,
                      4L,
                      12L));
      FunctionService functions =
          proxy(
              FunctionService.class,
              (method, args) -> {
                assertEquals("listFunctions", method);
                FunctionService.FunctionQuery query = (FunctionService.FunctionQuery) args[0];
                AddressScanOptions scan = query.scan();
                return Page.scanned(
                    List.of(),
                    query.limit(),
                    null,
                    new ScanProgress(
                        ScanProgress.Kind.ADDRESS,
                        scan.start(),
                        scan.end(),
                        null,
                        null,
                        true,
                        ScanProgress.StopReason.COMPLETED,
                        0));
              });
      TransactionRunner noTransactions =
          new TransactionRunner() {
            @Override
            public <T> T run(Operation<T> operation) {
              throw new AssertionError("batch.query must never open a transaction");
            }
          };
      AddressService addresses =
          proxy(
              AddressService.class,
              (method, args) -> {
                throw new ApiException(
                    404, "address_not_found", "address not found", "/selector/address");
              });
      BridgeServices services =
          new BridgeServices(
              program,
              addresses,
              unused(CommentService.class),
              unused(ReferenceService.class),
              unused(MemoryService.class),
              unused(ListingService.class),
              functions,
              unused(GlobalVariableService.class),
              analysis,
              unused(DecompilationService.class),
              unused(SymbolService.class),
              unused(DataTypeService.class),
              noTransactions,
              "sample.bin");
      this.registry =
          new ApiRegistry(
              services,
              "test-session",
              () -> {
                sessionGetCalls.incrementAndGet();
                return Map.of(
                    "id", "test-session", "status", "active", "program_name", "sample.bin");
              },
              () -> {});
    }
  }

  private interface MethodHandler {
    Object invoke(String method, Object[] args);
  }

  private static <T> T unused(Class<T> type) {
    return proxy(
        type,
        (method, args) -> {
          throw new AssertionError("Unexpected service call: " + method);
        });
  }

  private static <T> T proxy(Class<T> type, MethodHandler handler) {
    return type.cast(
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (proxy, method, args) -> handler.invoke(method.getName(), args)));
  }
}
