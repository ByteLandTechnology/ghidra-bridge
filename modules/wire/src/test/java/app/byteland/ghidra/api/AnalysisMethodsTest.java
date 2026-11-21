package app.byteland.ghidra.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class AnalysisMethodsTest {
  private static final Instant STARTED_AT = Instant.parse("2026-01-01T00:00:00Z");
  private static final Instant FINISHED_AT = Instant.parse("2026-01-01T00:00:05Z");

  @Test
  void cancelRunsDuringActiveAnalysisWhileProgramWritesRemainBlockedUntilStopped() throws Exception {
    AtomicInteger cancelCalls = new AtomicInteger();
    AtomicReference<AnalysisResource> current =
        new AtomicReference<>(
            new AnalysisResource(
                AnalysisResource.Kind.BRIDGE,
                AnalysisResource.Status.RUNNING,
                false,
                "task-1",
                STARTED_AT,
                null,
                25.0,
                null));

    AnalysisService analysis =
        new AnalysisService() {
          @Override
          public AnalysisResource startAnalysis(List<String> analyzers) {
            return current.get();
          }

          @Override
          public AnalysisResource getStatus() {
            return current.get();
          }

          @Override
          public AnalysisResource cancelAnalysis() {
            cancelCalls.incrementAndGet();
            return current.get();
          }

          @Override
          public void close() {}
        };

    ApiRegistry registry = registryWithAnalysis(analysis);
    ApiMethod<Map<String, Object>, Object> cancelMethod = registry.method("analysis.cancel");
    assertNotNull(cancelMethod);
    assertTrue(cancelMethod.effects().allowedDuringAnalysis());
    assertTrue(cancelMethod.effects().idempotent());
    assertFalse(cancelMethod.effects().destructive());

    ApiException blockedBeforeCancel =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "function.create",
                    Map.of("resource", Map.of("entry", "0x100000", "name", "fn_test"))));
    assertEquals(409, blockedBeforeCancel.status());
    assertEquals("analysis_in_progress", blockedBeforeCancel.error().code());

    Map<?, ?> whileStopping = (Map<?, ?>) registry.dispatch("analysis.cancel", Map.of());
    assertEquals(1, cancelCalls.get());
    assertEquals("running", whileStopping.get("status"));
    assertFalse(whileStopping.containsKey("error"));

    ApiException stillBlockedUntilStopped =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "function.create",
                    Map.of("resource", Map.of("entry", "0x100000", "name", "fn_test"))));
    assertEquals(409, stillBlockedUntilStopped.status());
    assertEquals("analysis_in_progress", stillBlockedUntilStopped.error().code());

    current.set(
        new AnalysisResource(
            AnalysisResource.Kind.BRIDGE,
            AnalysisResource.Status.CANCELLED,
            false,
            "task-1",
            STARTED_AT,
            FINISHED_AT,
            25.0,
            "analysis cancelled"));

    Map<?, ?> idempotentCancel = (Map<?, ?>) registry.dispatch("analysis.cancel", Map.of());
    assertEquals(2, cancelCalls.get());
    assertEquals("cancelled", idempotentCancel.get("status"));
    assertEquals("analysis cancelled", idempotentCancel.get("error"));
  }

  @Test
  void wireSerializationOmitsNullErrorAndProjectsTerminalFailureError() throws Exception {
    AtomicReference<AnalysisResource> current =
        new AtomicReference<>(
            new AnalysisResource(
                AnalysisResource.Kind.GHIDRA,
                AnalysisResource.Status.IDLE,
                false,
                null,
                null,
                null,
                null,
                null));

    AnalysisService analysis =
        new AnalysisService() {
          @Override
          public AnalysisResource startAnalysis(List<String> analyzers) {
            return current.get();
          }

          @Override
          public AnalysisResource getStatus() {
            return current.get();
          }

          @Override
          public AnalysisResource cancelAnalysis() {
            return current.get();
          }

          @Override
          public void close() {}
        };

    ApiRegistry registry = registryWithAnalysis(analysis);

    Map<?, ?> idle = (Map<?, ?>) registry.dispatch("analysis.get", Map.of());
    assertEquals("idle", idle.get("status"));
    assertFalse(idle.containsKey("error"));

    current.set(
        new AnalysisResource(
            AnalysisResource.Kind.BRIDGE,
            AnalysisResource.Status.COMPLETED,
            true,
            "task-ok",
            STARTED_AT,
            FINISHED_AT,
            100.0,
            null));
    Map<?, ?> completed = (Map<?, ?>) registry.dispatch("analysis.get", Map.of());
    assertEquals("completed", completed.get("status"));
    assertFalse(completed.containsKey("error"));

    current.set(
        new AnalysisResource(
            AnalysisResource.Kind.BRIDGE,
            AnalysisResource.Status.FAILED,
            false,
            "task-err",
            STARTED_AT,
            FINISHED_AT,
            null,
            "unknown analyzer: NonExistent"));
    Map<?, ?> failed = (Map<?, ?>) registry.dispatch("analysis.get", Map.of());
    assertEquals("failed", failed.get("status"));
    assertEquals("unknown analyzer: NonExistent", failed.get("error"));

    Map<?, ?> projected =
        (Map<?, ?>)
            registry.dispatch(
                "analysis.get",
                Map.of("projection", Map.of("fields", List.of("status", "error"))));
    assertEquals(
        Map.of("kind", "bridge", "status", "failed", "error", "unknown analyzer: NonExistent"),
        projected);
  }

  private static ApiRegistry registryWithAnalysis(AnalysisService analysis) {
    TransactionRunner transaction =
        new TransactionRunner() {
          @Override
          public <T> T run(Operation<T> operation) {
            try {
              return operation.execute();
            } catch (Exception ex) {
              throw new RuntimeException(ex);
            }
          }
        };
    BridgeServices services =
        new BridgeServices(
            unused(ProgramService.class),
            unused(AddressService.class),
            unused(CommentService.class),
            unused(ReferenceService.class),
            unused(MemoryService.class),
            unused(ListingService.class),
            unused(FunctionService.class),
            unused(GlobalVariableService.class),
            analysis,
            unused(DecompilationService.class),
            unused(SymbolService.class),
            unused(DataTypeService.class),
            transaction,
            "test");
    return new ApiRegistry(services, "test", Map::of, () -> {});
  }

  @SuppressWarnings("unchecked")
  private static <T> T unused(Class<T> type) {
    return (T)
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (proxy, method, args) -> {
              throw new AssertionError("unexpected call: " + method.getName());
            });
  }
}
