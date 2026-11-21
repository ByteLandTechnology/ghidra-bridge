package app.byteland.ghidra.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.api.ApiCatalog.MethodDescriptor;
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
import app.byteland.ghidra.service.program.ProgramResource;
import app.byteland.ghidra.service.program.ProgramService;
import app.byteland.ghidra.service.reference.ReferenceService;
import app.byteland.ghidra.service.symbol.SymbolService;
import java.lang.reflect.Proxy;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class BatchQueryMethodTest {

  @Test
  void batchQueryPublishesReadOnlyMetadataAndHints() {
    ApiCatalog catalog = ApiRegistry.catalog();
    assertEquals(57, catalog.methods().size());

    MethodDescriptor query =
        catalog.methods().stream()
            .filter(method -> "batch.query".equals(method.name()))
            .findFirst()
            .orElseThrow();
    assertTrue(query.readOnly());
    assertTrue(query.readOnlyHint());
    assertFalse(query.destructiveHint());
    assertTrue(query.idempotentHint());
    assertEquals(
        Map.of(
            "read_only", true,
            "mutates_program", false,
            "requires_transaction", false,
            "allowed_during_analysis", true,
            "destructive", false,
            "idempotent", true),
        query.contractValue().get("effects"));

    MethodDescriptor execute =
        catalog.methods().stream()
            .filter(method -> "batch.execute".equals(method.name()))
            .findFirst()
            .orElseThrow();
    assertFalse(execute.readOnly());
    assertFalse(execute.readOnlyHint());
    assertTrue(execute.destructiveHint());
    assertFalse(execute.idempotentHint());
  }

  @Test
  void batchQueryRunsDuringActiveAnalysisAndRejectsMutationsBeforeRunningAnyItem()
      throws Exception {
    AtomicInteger programReads = new AtomicInteger();
    AtomicBoolean analysisRunning = new AtomicBoolean(true);

    ProgramService programService =
        proxy(
            ProgramService.class,
            (method, args) -> {
              if ("getProgram".equals(method)) {
                programReads.incrementAndGet();
                return new ProgramResource(
                    "sample.bin",
                    "/tmp/sample.bin",
                    "ELF",
                    "ram:00100000",
                    "ram:00100000",
                    "ram:00101000",
                    "x86:LE:64:default",
                    "gcc",
                    Instant.EPOCH,
                    Instant.EPOCH,
                    4L,
                    8L);
              }
              throw new UnsupportedOperationException(method);
            });
    AnalysisService analysisService =
        proxy(
            AnalysisService.class,
            (method, args) ->
                new AnalysisResource(
                    AnalysisResource.Kind.GHIDRA,
                    analysisRunning.get()
                        ? AnalysisResource.Status.RUNNING
                        : AnalysisResource.Status.IDLE,
                    false,
                    null,
                    null,
                    null,
                    null));
    TransactionRunner transactionRunner =
        new TransactionRunner() {
          @Override
          public <T> T run(Operation<T> operation) {
            throw new AssertionError("batch.query must not open a transaction");
          }
        };

    BridgeServices services =
        new BridgeServices(
            programService,
            unused(AddressService.class),
            unused(CommentService.class),
            unused(ReferenceService.class),
            unused(MemoryService.class),
            unused(ListingService.class),
            unused(FunctionService.class),
            unused(GlobalVariableService.class),
            analysisService,
            unused(DecompilationService.class),
            unused(SymbolService.class),
            unused(DataTypeService.class),
            transactionRunner,
            "sample.bin");
    ApiRegistry registry =
        new ApiRegistry(
            services,
            "s1",
            () -> Map.of("id", "s1", "status", "active", "program_name", "sample.bin"),
            () -> {});

    @SuppressWarnings("unchecked")
    Map<String, Object> response =
        (Map<String, Object>)
            registry.dispatch(
                "batch.query",
                Map.of(
                    "transaction_mode",
                    "per_item",
                    "items",
                    List.of(
                        Map.of("id", "p", "method", "program.get", "arguments", Map.of()),
                        Map.of("id", "s", "method", "session.get", "arguments", Map.of()))));
    @SuppressWarnings("unchecked")
    List<Map<String, Object>> items = (List<Map<String, Object>>) response.get("items");
    assertEquals(2, items.size());
    assertEquals("p", items.get(0).get("id"));
    assertNotNull(items.get(0).get("result"));
    assertEquals("s", items.get(1).get("id"));
    assertNotNull(items.get(1).get("result"));
    assertEquals(1, programReads.get());

    // Prevalidation must reject a mutation item with 400 validation_failed before running item 0.
    ApiException mutationRejected =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "batch.query",
                    Map.of(
                        "items",
                        List.of(
                            Map.of("id", "read1", "method", "program.get", "arguments", Map.of()),
                            Map.of(
                                "id",
                                "mut1",
                                "method",
                                "comment.create",
                                "arguments",
                                Map.of(
                                    "resource",
                                    Map.of(
                                        "address", "ram:00100000",
                                        "type", "plate",
                                        "text", "note")))))));
    assertEquals(400, mutationRejected.error().status());
    assertEquals("validation_failed", mutationRejected.error().code());
    assertEquals("/items", mutationRejected.error().target());
    assertEquals(1, programReads.get(), "prevalidation must reject before executing item 0");

    // Non-batchable read-only metadata methods (such as interface.get or batch.query) also fail.
    ApiException nestedRejected =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "batch.query",
                    Map.of(
                        "items",
                        List.of(
                            Map.of(
                                "id", "nested", "method", "interface.get", "arguments", Map.of())))));
    assertEquals(400, nestedRejected.error().status());
    assertEquals("validation_failed", nestedRejected.error().code());
  }

  @FunctionalInterface
  private interface CallHandler {
    Object invoke(String method, Object[] args) throws Exception;
  }

  @SuppressWarnings("unchecked")
  private static <T> T proxy(Class<T> type, CallHandler handler) {
    return (T)
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (proxy, method, args) -> {
              if (method.getDeclaringClass() == Object.class) {
                return method.invoke(handler, args);
              }
              return handler.invoke(method.getName(), args == null ? new Object[0] : args);
            });
  }

  private static <T> T unused(Class<T> type) {
    return proxy(
        type,
        (method, args) -> {
          if ("close".equals(method)) return null;
          throw new AssertionError("Unexpected service call: " + type.getSimpleName() + "." + method);
        });
  }
}
