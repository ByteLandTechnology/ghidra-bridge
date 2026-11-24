package app.byteland.ghidra.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.ScanProgress;
import app.byteland.ghidra.service.TransactionRunner;
import app.byteland.ghidra.service.address.AddressService;
import app.byteland.ghidra.service.analysis.AnalysisResource;
import app.byteland.ghidra.service.analysis.AnalysisService;
import app.byteland.ghidra.service.comment.CommentResource;
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class ScanListFilterTest {
  private static final List<String> OPTIONAL_FILTER_SCAN_METHODS =
      List.of(
          "code_unit.list",
          "data_unit.list",
          "instruction.list",
          "reference.list",
          "global_variable.list",
          "comment.list",
          "function.list",
          "symbol.list");

  @Test
  void canonicalSchemaPassesFilterThroughUnchanged() {
    Map<String, Object> filterSchema =
        WireSchema.object(
            ApiSchemaCatalog.props(
                "start", WireSchema.string(),
                "end", WireSchema.string(),
                "kind", WireSchema.string()));
    Map<String, Object> canonical =
        StrictObjectCodec.canonicalSchema(ApiSchemaCatalog.scanListInput(filterSchema));

    @SuppressWarnings("unchecked")
    Map<String, Object> properties = (Map<String, Object>) canonical.get("properties");
    assertEquals(filterSchema, properties.get("filter"));

    ApiCatalog catalog = ApiRegistry.catalog();
    assertEquals(Map.of(), filterProperties(catalog, "data_unit.list"));
    assertEquals(Map.of(), filterProperties(catalog, "instruction.list"));
    assertEquals(Set.of("kind"), filterProperties(catalog, "code_unit.list").keySet());
    assertEquals(
        List.of("from", "to", "type", "direction", "selector"),
        List.copyOf(filterProperties(catalog, "reference.list").keySet()));
    assertEquals(
        List.of("name", "namespace", "case_sensitive"),
        List.copyOf(filterProperties(catalog, "global_variable.list").keySet()));
    assertEquals(
        List.of("address", "type", "text"),
        List.copyOf(filterProperties(catalog, "comment.list").keySet()));
    for (String method : OPTIONAL_FILTER_SCAN_METHODS) {
      Map<String, Object> filterProps = filterProperties(catalog, method);
      assertFalse(filterProps.containsKey("start"), method + " must not expose filter.start");
      assertFalse(filterProps.containsKey("end"), method + " must not expose filter.end");
    }
  }

  @Test
  void directAndBatchRequestsRejectLegacyFilterRangeFieldsWithUnknownField() {
    TestHarness harness = new TestHarness();

    for (String method : OPTIONAL_FILTER_SCAN_METHODS) {
      for (String legacyKey : List.of("start", "end")) {
        Map<String, Object> params = Map.of("filter", Map.of(legacyKey, "0x1000"));
        ApiException directError =
            assertThrows(
                ApiException.class,
                () -> harness.registry.dispatch(method, params),
                method + " direct filter." + legacyKey);
        assertEquals(400, directError.status());
        assertEquals("unknown_field", directError.error().code());
        assertEquals("/filter/" + legacyKey, directError.error().target());

        assertBatchUnknownField(harness.registry, method, params, "/filter/" + legacyKey);
      }
    }

    for (String legacyKey : List.of("start", "end")) {
      Map<String, Object> flowFilter = new LinkedHashMap<>();
      flowFilter.put("selector", Map.of("kind", "address", "address", "0x1000"));
      flowFilter.put(legacyKey, "0x1000");
      Map<String, Object> params = Map.of("filter", flowFilter);

      ApiException directError =
          assertThrows(
              ApiException.class, () -> harness.registry.dispatch("flow_override.list", params));
      assertEquals(400, directError.status());
      assertEquals("unknown_field", directError.error().code());
      assertEquals("/filter/" + legacyKey, directError.error().target());

      assertBatchUnknownField(
          harness.registry, "flow_override.list", params, "/filter/" + legacyKey);
    }
  }

  @Test
  void scanListMethodsResolveScanRangeAndTimeoutOptions() throws Exception {
    TestHarness harness = new TestHarness();
    Map<String, Object> scanParams =
        Map.of(
            "scan",
            Map.of(
                "range", Map.of("start", "0x1000", "end", "0x2000"),
                "timeout_ms", 2500));
    AddressScanOptions expected = new AddressScanOptions("0x1000", "0x2000", 2500);

    harness.registry.dispatch("code_unit.list", scanParams);
    assertEquals(expected, harness.lastScan.get());

    harness.registry.dispatch("data_unit.list", scanParams);
    assertEquals(expected, harness.lastScan.get());

    harness.registry.dispatch("instruction.list", scanParams);
    assertEquals(expected, harness.lastScan.get());

    harness.registry.dispatch("reference.list", scanParams);
    assertEquals(expected, harness.lastScan.get());

    harness.registry.dispatch("global_variable.list", scanParams);
    assertEquals(expected, harness.lastScan.get());

    harness.registry.dispatch("function.list", scanParams);
    assertEquals(expected, harness.lastScan.get());

    harness.registry.dispatch(
        "symbol.list",
        Map.of(
            "filter", Map.of("address", "0x1500"),
            "scan",
                Map.of(
                    "range", Map.of("start", "0x1000", "end", "0x2000"),
                    "timeout_ms", 2500)));
    assertEquals(expected, harness.lastSymbolQuery.get().scan());
    assertEquals("0x1500", harness.lastSymbolQuery.get().address());

    harness.registry.dispatch(
        "flow_override.list",
        Map.of(
            "filter", Map.of("selector", Map.of("kind", "address", "address", "0x1000")),
            "scan", Map.of("timeout_ms", 1800)));
    assertEquals(new AddressScanOptions(null, null, 1800), harness.lastScan.get());
  }

  @Test
  void commentListResolvesFilterAddressAndRejectsConflictingRangeStart() throws Exception {
    TestHarness harness = new TestHarness();

    harness.registry.dispatch(
        "comment.list",
        Map.of(
            "filter", Map.of("address", "0x1000", "type", "eol", "text", "note"),
            "scan", Map.of("range", Map.of("end", "0x2000"), "timeout_ms", 1500)));
    CommentService.CommentQuery fallbackQuery = harness.lastCommentQuery.get();
    assertEquals(new AddressScanOptions("0x1000", "0x2000", 1500), fallbackQuery.scan());
    assertEquals(CommentResource.Type.EOL, fallbackQuery.type());
    assertEquals("note", fallbackQuery.text());

    harness.registry.dispatch(
        "comment.list",
        Map.of(
            "filter", Map.of("address", "0x1000"),
            "scan", Map.of("range", Map.of("start", "0x1000", "end", "0x2000"))));
    assertEquals(
        new AddressScanOptions("0x1000", "0x2000", AddressScanOptions.DEFAULT_TIMEOUT_MS),
        harness.lastCommentQuery.get().scan());

    Map<String, Object> conflicting =
        Map.of(
            "filter", Map.of("address", "0x1000"),
            "scan", Map.of("range", Map.of("start", "0x2000")));
    ApiException directConflict =
        assertThrows(
            ApiException.class, () -> harness.registry.dispatch("comment.list", conflicting));
    assertEquals(400, directConflict.status());
    assertEquals("conflicting_range", directConflict.error().code());
    assertEquals("range.start conflicts with filter.address", directConflict.error().message());
    assertEquals("/scan/range/start", directConflict.error().target());

    @SuppressWarnings("unchecked")
    Map<String, Object> perItemBatch =
        (Map<String, Object>)
            harness.registry.dispatch(
                "batch.execute",
                Map.of(
                    "transaction_mode",
                    "per_item",
                    "items",
                    List.of(
                        Map.of(
                            "id", "c1",
                            "method", "comment.list",
                            "arguments", conflicting))));
    @SuppressWarnings("unchecked")
    List<Map<String, Object>> rows = (List<Map<String, Object>>) perItemBatch.get("items");
    @SuppressWarnings("unchecked")
    Map<String, Object> itemError = (Map<String, Object>) rows.getFirst().get("error");
    assertEquals(400, itemError.get("status"));
    assertEquals("conflicting_range", itemError.get("code"));
    assertEquals("/scan/range/start", itemError.get("target"));

    ApiException allOrNoneConflict =
        assertThrows(
            ApiException.class,
            () ->
                harness.registry.dispatch(
                    "batch.execute",
                    Map.of(
                        "transaction_mode",
                        "all_or_none",
                        "items",
                        List.of(
                            Map.of(
                                "id", "c1",
                                "method", "comment.list",
                                "arguments", conflicting)))));
    assertEquals(409, allOrNoneConflict.status());
    assertEquals("batch_rolled_back", allOrNoneConflict.error().code());
    @SuppressWarnings("unchecked")
    Map<String, Object> cause =
        (Map<String, Object>) allOrNoneConflict.error().details().get("cause");
    assertEquals(400, cause.get("status"));
    assertEquals("conflicting_range", cause.get("code"));
    assertEquals("/scan/range/start", cause.get("target"));
  }

  @SuppressWarnings("unchecked")
  private static void assertBatchUnknownField(
      ApiRegistry registry,
      String method,
      Map<String, Object> arguments,
      String expectedSuffix) {
    ApiException batchError =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "batch.execute",
                    Map.of(
                        "items",
                        List.of(
                            Map.of(
                                "id", "item-1",
                                "method", method,
                                "arguments", arguments)))));
    assertEquals(400, batchError.status());
    assertEquals("validation_failed", batchError.error().code());
    List<Map<String, Object>> violations =
        (List<Map<String, Object>>) batchError.error().details().get("violations");
    assertEquals(1, violations.size());
    assertEquals("unknown_field", violations.getFirst().get("code"));
    assertEquals("/items/0/arguments" + expectedSuffix, violations.getFirst().get("target"));
    assertTrue(String.valueOf(violations.getFirst().get("message")).contains("not allowed"));
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> filterProperties(ApiCatalog catalog, String methodName) {
    ApiCatalog.MethodDescriptor descriptor =
        catalog.methods().stream()
            .filter(method -> method.name().equals(methodName))
            .findFirst()
            .orElseThrow();
    Map<String, Object> properties =
        (Map<String, Object>) descriptor.inputSchema().get("properties");
    Map<String, Object> filter = (Map<String, Object>) properties.get("filter");
    return (Map<String, Object>) filter.get("properties");
  }

  private static final class TestHarness {
    final AtomicReference<AddressScanOptions> lastScan = new AtomicReference<>();
    final AtomicReference<CommentService.CommentQuery> lastCommentQuery = new AtomicReference<>();
    final AtomicReference<SymbolService.SymbolQuery> lastSymbolQuery = new AtomicReference<>();
    final ApiRegistry registry;

    TestHarness() {
      AnalysisService analysis =
          proxy(
              AnalysisService.class,
              (method, args) ->
                  new AnalysisResource(
                      AnalysisResource.Kind.GHIDRA,
                      AnalysisResource.Status.IDLE,
                      false,
                      null,
                      null,
                      null,
                      null));
      ListingService listing =
          proxy(
              ListingService.class,
              (method, args) -> {
                AddressScanOptions scan =
                    switch (method) {
                      case "listCodeUnits", "listInstructions", "listDataUnits" ->
                          (AddressScanOptions) args[0];
                      case "getFlowOverrides" -> (AddressScanOptions) args[2];
                      default -> throw new AssertionError(method);
                    };
                lastScan.set(scan);
                int limit =
                    switch (method) {
                      case "listCodeUnits", "listInstructions", "listDataUnits" -> (Integer) args[1];
                      case "getFlowOverrides" -> (Integer) args[3];
                      default -> 100;
                    };
                return emptyScannedPage(scan, limit);
              });
      ReferenceService references =
          (fromRaw, toRaw, type, direction, scope, scan, limit, cursor) -> {
            lastScan.set(scan);
            return emptyScannedPage(scan, limit);
          };
      GlobalVariableService globalVariables =
          proxy(
              GlobalVariableService.class,
              (method, args) -> {
                assertEquals("listGlobalVariables", method);
                GlobalVariableService.Query query = (GlobalVariableService.Query) args[0];
                lastScan.set(query.scan());
                return emptyScannedPage(query.scan(), query.limit());
              });
      FunctionService functions =
          proxy(
              FunctionService.class,
              (method, args) -> {
                assertEquals("listFunctions", method);
                FunctionService.FunctionQuery query = (FunctionService.FunctionQuery) args[0];
                lastScan.set(query.scan());
                return emptyScannedPage(query.scan(), query.limit());
              });
      SymbolService symbols =
          proxy(
              SymbolService.class,
              (method, args) -> {
                assertEquals("listSymbols", method);
                SymbolService.SymbolQuery query = (SymbolService.SymbolQuery) args[0];
                lastSymbolQuery.set(query);
                lastScan.set(query.scan());
                return emptyScannedPage(query.scan(), query.limit());
              });
      CommentService comments =
          proxy(
              CommentService.class,
              (method, args) -> {
                assertEquals("listComments", method);
                CommentService.CommentQuery query = (CommentService.CommentQuery) args[0];
                lastCommentQuery.set(query);
                lastScan.set(query.scan());
                return emptyScannedPage(query.scan(), query.limit());
              });
      TransactionRunner transaction =
          new TransactionRunner() {
            @Override
            public <T> T run(Operation<T> operation) {
              try {
                return operation.execute();
              } catch (RuntimeException error) {
                throw error;
              } catch (Exception error) {
                throw new RuntimeException(error);
              }
            }
          };
      BridgeServices services =
          new BridgeServices(
              unused(ProgramService.class),
              unused(AddressService.class),
              comments,
              references,
              unused(MemoryService.class),
              listing,
              functions,
              globalVariables,
              analysis,
              unused(DecompilationService.class),
              symbols,
              unused(DataTypeService.class),
              transaction,
              "test");
      this.registry = new ApiRegistry(services, "test", Map::of, () -> {});
      assertNull(lastScan.get());
    }
  }

  private static <T> Page<T> emptyScannedPage(AddressScanOptions scan, int limit) {
    return Page.scanned(
        List.of(),
        limit,
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
