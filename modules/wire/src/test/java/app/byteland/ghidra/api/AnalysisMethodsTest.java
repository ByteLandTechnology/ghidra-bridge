package app.byteland.ghidra.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

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
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class AnalysisMethodsTest {
  @Test
  void serializesNonNullTelemetryAndOmitsNullFields() throws Exception {
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
                null,
                null));
    AnalysisResource startedSnapshot =
        new AnalysisResource(
            AnalysisResource.Kind.BRIDGE,
            AnalysisResource.Status.RUNNING,
            false,
            "task-1",
            Instant.parse("2026-01-01T00:00:00Z"),
            null,
            37.5,
            "Decompiler Parameter ID",
            null);
    AnalysisService analysis =
        new AnalysisService() {
          @Override
          public AnalysisResource startAnalysis(List<String> analyzers) {
            assertEquals(List.of("Decompiler Parameter ID"), analyzers);
            current.set(startedSnapshot);
            return startedSnapshot;
          }

          @Override
          public AnalysisResource getStatus() {
            return current.get();
          }

          @Override
          public void close() {}
        };
    ApiRegistry registry = registryWith(analysis);

    Map<?, ?> idle = (Map<?, ?>) registry.dispatch("analysis.get", Map.of());
    assertEquals("ghidra", idle.get("kind"));
    assertEquals("idle", idle.get("status"));
    assertEquals(false, idle.get("analyzed"));
    assertFalse(idle.containsKey("message"));
    assertFalse(idle.containsKey("error"));

    Map<?, ?> running =
        (Map<?, ?>)
            registry.dispatch(
                "analysis.start", Map.of("analyzers", List.of("Decompiler Parameter ID")));
    assertEquals("bridge", running.get("kind"));
    assertEquals("running", running.get("status"));
    assertEquals("task-1", running.get("task_id"));
    assertEquals(37.5, running.get("progress"));
    assertEquals("Decompiler Parameter ID", running.get("message"));
    assertFalse(running.containsKey("error"));

    current.set(
        new AnalysisResource(
            AnalysisResource.Kind.BRIDGE,
            AnalysisResource.Status.FAILED,
            false,
            "task-1",
            Instant.parse("2026-01-01T00:00:00Z"),
            Instant.parse("2026-01-01T00:00:05Z"),
            37.5,
            "Decompiler Parameter ID",
            "analyzer crashed"));

    Map<?, ?> failed = (Map<?, ?>) registry.dispatch("analysis.get", Map.of());
    assertEquals("failed", failed.get("status"));
    assertEquals("Decompiler Parameter ID", failed.get("message"));
    assertEquals("analyzer crashed", failed.get("error"));

    Map<?, ?> projected =
        (Map<?, ?>)
            registry.dispatch(
                "analysis.get",
                Map.of("projection", Map.of("fields", List.of("status", "message", "error"))));
    assertEquals(
        Map.of(
            "kind", "bridge",
            "status", "failed",
            "message", "Decompiler Parameter ID",
            "error", "analyzer crashed"),
        projected);
  }

  @Test
  void rejectsInvalidAnalyzersSynchronouslyWithHttp400() {
    AnalysisService analysis =
        new AnalysisService() {
          @Override
          public AnalysisResource startAnalysis(List<String> analyzers) {
            for (String analyzer : analyzers) {
              if (analyzer.isBlank()) {
                throw new IllegalArgumentException("analyzer name must not be blank");
              }
            }
            throw new IllegalArgumentException("unknown analyzer: " + analyzers.getFirst());
          }

          @Override
          public AnalysisResource getStatus() {
            return new AnalysisResource(
                AnalysisResource.Kind.GHIDRA,
                AnalysisResource.Status.IDLE,
                false,
                null,
                null,
                null,
                null,
                null,
                null);
          }

          @Override
          public void close() {}
        };
    ApiRegistry registry = registryWith(analysis);

    IllegalArgumentException unknownAnalyzer =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                registry.dispatch(
                    "analysis.start", Map.of("analyzers", List.of("NoSuchAnalyzer"))));
    ApiFailures.Failure normalized = ApiFailures.normalize(unknownAnalyzer);
    assertEquals(400, normalized.status());
    assertEquals("invalid_request", normalized.error().code());
    assertEquals("unknown analyzer: NoSuchAnalyzer", normalized.error().message());

    IllegalArgumentException whitespaceName =
        assertThrows(
            IllegalArgumentException.class,
            () -> registry.dispatch("analysis.start", Map.of("analyzers", List.of("   "))));
    ApiFailures.Failure normalizedWhitespace = ApiFailures.normalize(whitespaceName);
    assertEquals(400, normalizedWhitespace.status());
    assertEquals("invalid_request", normalizedWhitespace.error().code());

    ApiException emptyList =
        assertThrows(
            ApiException.class,
            () -> registry.dispatch("analysis.start", Map.of("analyzers", List.of())));
    assertEquals(400, emptyList.status());

    ApiException emptyString =
        assertThrows(
            ApiException.class,
            () -> registry.dispatch("analysis.start", Map.of("analyzers", List.of(""))));
    assertEquals(400, emptyString.status());
  }

  private static ApiRegistry registryWith(AnalysisService analysis) {
    TransactionRunner transaction =
        new TransactionRunner() {
          @Override
          public <T> T run(Operation<T> operation) {
            throw new AssertionError("analysis methods do not open outer bridge transactions");
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

  private static <T> T unused(Class<T> type) {
    return type.cast(
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (proxy, method, args) -> {
              throw new AssertionError(method.getName());
            }));
  }
}
