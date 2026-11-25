package app.byteland.ghidra.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
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
import app.byteland.ghidra.service.program.ProgramHistoryConflictException;
import app.byteland.ghidra.service.program.ProgramHistoryResource;
import app.byteland.ghidra.service.program.ProgramService;
import app.byteland.ghidra.service.program.ProgramUndoRedoResult;
import app.byteland.ghidra.service.reference.ReferenceService;
import app.byteland.ghidra.service.symbol.SymbolService;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;

class ProgramHistoryMethodTest {
  @Test
  void historyUndoAndRedoUseExpectedEffectsSchemasAndTransactionNames() throws Exception {
    List<String> transactionNames = new ArrayList<>();
    AtomicBoolean analysisRunning = new AtomicBoolean(false);
    AtomicBoolean canUndo = new AtomicBoolean(false);
    AtomicBoolean canRedo = new AtomicBoolean(false);

    ProgramService programs =
        proxy(
            ProgramService.class,
            (method, args) ->
                switch (method) {
                  case "getHistory" ->
                      new ProgramHistoryResource(
                          canUndo.get(),
                          canRedo.get(),
                          canUndo.get() ? "symbol.demangle" : null,
                          canRedo.get() ? "symbol.demangle" : null,
                          canUndo.get() ? List.of("symbol.demangle") : List.of(),
                          canRedo.get() ? List.of("symbol.demangle") : List.of());
                  case "undo" -> {
                    if (!canUndo.get()) {
                      throw ProgramHistoryConflictException.nothingToUndo();
                    }
                    canUndo.set(false);
                    canRedo.set(true);
                    yield new ProgramUndoRedoResult(
                        "undo",
                        "symbol.demangle",
                        false,
                        true,
                        null,
                        "symbol.demangle",
                        List.of(),
                        List.of("symbol.demangle"));
                  }
                  case "redo" -> {
                    if (!canRedo.get()) {
                      throw ProgramHistoryConflictException.nothingToRedo();
                    }
                    canUndo.set(true);
                    canRedo.set(false);
                    yield new ProgramUndoRedoResult(
                        "redo",
                        "symbol.demangle",
                        true,
                        false,
                        "symbol.demangle",
                        null,
                        List.of("symbol.demangle"),
                        List.of());
                  }
                  default -> throw new AssertionError(method);
                });

    SymbolService symbols =
        proxy(
            SymbolService.class,
            (method, args) -> {
              assertEquals("demangleSymbols", method);
              canUndo.set(true);
              canRedo.set(false);
              return new SymbolService.DemangleResult(1, 0, List.of());
            });

    AnalysisService analysis =
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

    TransactionRunner transaction =
        new TransactionRunner() {
          @Override
          public <T> T run(Operation<T> operation) {
            return run("default", operation);
          }

          @Override
          public <T> T run(String description, Operation<T> operation) {
            transactionNames.add(description);
            try {
              return operation.execute();
            } catch (Exception ex) {
              throw new RuntimeException(ex);
            }
          }
        };

    BridgeServices services =
        new BridgeServices(
            programs,
            unused(AddressService.class),
            unused(CommentService.class),
            unused(ReferenceService.class),
            unused(MemoryService.class),
            unused(ListingService.class),
            unused(FunctionService.class),
            unused(GlobalVariableService.class),
            analysis,
            unused(DecompilationService.class),
            symbols,
            unused(DataTypeService.class),
            transaction,
            "test");
    ApiRegistry registry = new ApiRegistry(services, "test", Map::of, () -> {});

    Map<?, ?> initial = (Map<?, ?>) registry.dispatch("program.history", Map.of());
    assertEquals(Boolean.FALSE, initial.get("can_undo"));
    assertEquals(Boolean.FALSE, initial.get("can_redo"));
    assertNull(initial.get("undo_name"));
    assertNull(initial.get("redo_name"));
    assertEquals(List.of(), initial.get("undo_list"));
    assertEquals(List.of(), initial.get("redo_list"));

    var emptyUndo =
        ApiFailures.normalize(
            assertThrows(
                ProgramHistoryConflictException.class,
                () -> registry.dispatch("program.undo", Map.of())));
    assertEquals(409, emptyUndo.status());
    assertEquals("nothing_to_undo", emptyUndo.error().code());

    registry.dispatch("symbol.demangle", Map.of());
    assertEquals(List.of("symbol.demangle"), transactionNames);

    Map<?, ?> afterWrite = (Map<?, ?>) registry.dispatch("program.history", Map.of());
    assertEquals(Boolean.TRUE, afterWrite.get("can_undo"));
    assertEquals("symbol.demangle", afterWrite.get("undo_name"));

    Map<?, ?> undone = (Map<?, ?>) registry.dispatch("program.undo", Map.of());
    assertEquals("undo", undone.get("action"));
    assertEquals("symbol.demangle", undone.get("transaction_name"));
    assertEquals(Boolean.FALSE, undone.get("can_undo"));
    assertEquals(Boolean.TRUE, undone.get("can_redo"));
    assertEquals("symbol.demangle", undone.get("redo_name"));
    assertEquals(1, transactionNames.size());

    Map<?, ?> redone = (Map<?, ?>) registry.dispatch("program.redo", Map.of());
    assertEquals("redo", redone.get("action"));
    assertEquals("symbol.demangle", redone.get("transaction_name"));
    assertEquals(Boolean.TRUE, redone.get("can_undo"));
    assertEquals(Boolean.FALSE, redone.get("can_redo"));
    assertEquals(1, transactionNames.size());

    registry.dispatch(
        "batch.execute",
        Map.of(
            "transaction_mode",
            "all_or_none",
            "items",
            List.of(
                Map.of("id", "item-1", "method", "symbol.demangle", "arguments", Map.of()))));
    assertEquals(List.of("symbol.demangle", "batch.execute"), transactionNames);

    ApiException batchUndoRejected =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "batch.execute",
                    Map.of(
                        "items",
                        List.of(
                            Map.of("id", "u1", "method", "program.undo", "arguments", Map.of())))));
    assertEquals(400, batchUndoRejected.status());

    analysisRunning.set(true);
    ApiException undoDuringAnalysis =
        assertThrows(ApiException.class, () -> registry.dispatch("program.undo", Map.of()));
    assertEquals(409, undoDuringAnalysis.status());
    assertEquals("analysis_in_progress", undoDuringAnalysis.error().code());

    ApiException redoDuringAnalysis =
        assertThrows(ApiException.class, () -> registry.dispatch("program.redo", Map.of()));
    assertEquals(409, redoDuringAnalysis.status());
    assertEquals("analysis_in_progress", redoDuringAnalysis.error().code());

    Map<?, ?> historyDuringAnalysis = (Map<?, ?>) registry.dispatch("program.history", Map.of());
    assertTrue((Boolean) historyDuringAnalysis.get("can_undo"));
    assertFalse(registry.method("program.undo").effects().batchable());
    assertFalse(registry.method("program.redo").effects().batchable());
  }

  private interface Handler {
    Object invoke(String method, Object[] args);
  }

  private static <T> T unused(Class<T> type) {
    return proxy(
        type,
        (method, args) -> {
          throw new AssertionError(method);
        });
  }

  private static <T> T proxy(Class<T> type, Handler handler) {
    return type.cast(
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (proxy, method, args) -> handler.invoke(method.getName(), args)));
  }
}
