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
import app.byteland.ghidra.service.comment.CommentService;
import app.byteland.ghidra.service.datatype.DataTypeService;
import app.byteland.ghidra.service.decompilation.DecompilationService;
import app.byteland.ghidra.service.function.FunctionCallGraphResource;
import app.byteland.ghidra.service.function.FunctionCallGraphResource.BranchStateResource;
import app.byteland.ghidra.service.function.FunctionCallGraphResource.BranchesResource;
import app.byteland.ghidra.service.function.FunctionCallGraphResource.EdgeResource;
import app.byteland.ghidra.service.function.FunctionCallGraphResource.FunctionCallGraphQuery;
import app.byteland.ghidra.service.function.FunctionCallGraphResource.NodeResource;
import app.byteland.ghidra.service.function.FunctionCallResource;
import app.byteland.ghidra.service.function.FunctionService;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService;
import app.byteland.ghidra.service.listing.BasicBlockResource;
import app.byteland.ghidra.service.listing.BasicBlockResource.FlowEdge;
import app.byteland.ghidra.service.listing.BasicBlockResource.InstructionSummary;
import app.byteland.ghidra.service.listing.FlowOverrideScope;
import app.byteland.ghidra.service.listing.ListingService;
import app.byteland.ghidra.service.memory.MemoryService;
import app.byteland.ghidra.service.program.ProgramService;
import app.byteland.ghidra.service.reference.ReferenceResource;
import app.byteland.ghidra.service.reference.ReferenceService;
import app.byteland.ghidra.service.reference.ReferenceService.ReferenceQuery;
import app.byteland.ghidra.service.symbol.SymbolService;
import java.lang.reflect.Proxy;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class CallSiteAndGraphMethodsTest {
  @Test
  void functionCallListPreservesSiblingSitesAndSyntheticNullSite() throws Exception {
    List<FunctionCallResource> allRows =
        List.of(
            new FunctionCallResource(
                "ram:00101000",
                "alpha",
                "ram:00102004",
                FunctionCallResource.Direction.CALLEES,
                "Global",
                null),
            new FunctionCallResource(
                "ram:00101000",
                "alpha",
                "ram:00102018",
                FunctionCallResource.Direction.CALLEES,
                "Global",
                null),
            new FunctionCallResource(
                "ram:00103000",
                "synthetic_peer",
                null,
                FunctionCallResource.Direction.CALLEES,
                "Global",
                null));

    FunctionService functions =
        proxy(
            FunctionService.class,
            (method, args) -> {
              assertEquals("getCallees", method);
              int limit = (Integer) args[1];
              String cursor = (String) args[2];
              return Page.paginate(
                  allRows,
                  limit,
                  cursor,
                  row ->
                      row.entry() + '\0' + (row.callSite() == null ? "-" : row.callSite()));
            });

    ApiRegistry registry = registryWith(functions, unused(ListingService.class), unused(ReferenceService.class));

    @SuppressWarnings("unchecked")
    Map<String, Object> firstPage =
        (Map<String, Object>)
            registry.dispatch(
                "function_call.list",
                Map.of(
                    "filter", Map.of("entry", "0x102000", "direction", "callees"),
                    "page", Map.of("limit", 1)));
    @SuppressWarnings("unchecked")
    List<Map<String, Object>> firstItems = (List<Map<String, Object>>) firstPage.get("items");
    assertEquals(1, firstItems.size());
    assertEquals("ram:00101000", firstItems.getFirst().get("entry"));
    assertEquals("ram:00102004", firstItems.getFirst().get("call_site"));
    String cursor1 = (String) firstPage.get("next_cursor");
    assertTrue(cursor1 != null && !cursor1.isBlank());

    @SuppressWarnings("unchecked")
    Map<String, Object> secondPage =
        (Map<String, Object>)
            registry.dispatch(
                "function_call.list",
                Map.of(
                    "filter", Map.of("entry", "0x102000", "direction", "callees"),
                    "page", Map.of("limit", 2, "cursor", cursor1)));
    @SuppressWarnings("unchecked")
    List<Map<String, Object>> secondItems = (List<Map<String, Object>>) secondPage.get("items");
    assertEquals(2, secondItems.size());
    assertEquals("ram:00102018", secondItems.get(0).get("call_site"));
    assertEquals("ram:00103000", secondItems.get(1).get("entry"));
    assertFalse(secondItems.get(1).containsKey("call_site"));
    assertNull(secondPage.get("next_cursor"));
  }

  @Test
  void functionCallGraphGetValidatesBoundsAndSerializesNodesAndEdges() throws Exception {
    AtomicReference<FunctionCallGraphQuery> captured = new AtomicReference<>();
    FunctionService functions =
        proxy(
            FunctionService.class,
            (method, args) -> {
              assertEquals("getCallGraph", method);
              FunctionCallGraphQuery query = (FunctionCallGraphQuery) args[0];
              captured.set(query);
              return new FunctionCallGraphResource(
                  "ram:00102000",
                  List.of(
                      new NodeResource(
                          "ram:00102000",
                          "root_fn",
                          "Global",
                          null,
                          null,
                          null,
                          new BranchesResource(
                              new BranchStateResource(true, 1),
                              new BranchStateResource(false, null))),
                      new NodeResource(
                          "ram:00101000", "caller_fn", "Global", null, 1, null, null)),
                  List.of(
                      new EdgeResource(
                          "ram:00101000",
                          "ram:00102000",
                          List.of("ram:00101010", "ram:00101024"))),
                  false,
                  "completed",
                  4L);
            });

    ApiRegistry registry = registryWith(functions, unused(ListingService.class), unused(ReferenceService.class));
    assertTrue(registry.method("function_call_graph.get").effects().readOnly());

    @SuppressWarnings("unchecked")
    Map<String, Object> result =
        (Map<String, Object>)
            registry.dispatch(
                "function_call_graph.get",
                Map.of(
                    "selector", Map.of("entry", "0x102000"),
                    "callers_depth", 3,
                    "callees_depth", 1,
                    "max_nodes", 80,
                    "max_edges", 240,
                    "expansion", Map.of("callers", List.of("0x102000"), "callees", List.of()),
                    "scan", Map.of("timeout_ms", 5000)));

    assertEquals("0x102000", captured.get().entry());
    assertEquals(3, captured.get().callersDepth());
    assertEquals(1, captured.get().calleesDepth());
    assertEquals(80, captured.get().maxNodes());
    assertEquals(240, captured.get().maxEdges());
    assertEquals(5000, captured.get().timeoutMs());
    assertEquals(List.of("0x102000"), captured.get().expansion().callers());
    assertEquals("ram:00102000", result.get("root"));
    assertEquals(false, result.get("limited"));

    assertThrows(
        ApiException.class,
        () ->
            registry.dispatch(
                "function_call_graph.get",
                Map.of("selector", Map.of("entry", "0x102000"), "callers_depth", 9)));
  }

  @Test
  void basicBlockListPreservesFlowEdgeTypesAndScanProgress() throws Exception {
    AtomicReference<FlowOverrideScope> capturedScope = new AtomicReference<>();
    AtomicReference<Integer> capturedMaxEdges = new AtomicReference<>();
    ListingService listing =
        proxy(
            ListingService.class,
            (method, args) -> {
              assertEquals("listBasicBlocks", method);
              capturedScope.set((FlowOverrideScope) args[0]);
              capturedMaxEdges.set((Integer) args[2]);
              BasicBlockResource block =
                  new BasicBlockResource(
                      "ram:00102000",
                      "ram:00102005",
                      6L,
                      "CONDITIONAL_JUMP",
                      false,
                      false,
                      List.of(
                          new InstructionSummary(
                              "ram:00102000",
                              4,
                              "CMP",
                              List.of("EDI", "0x0"),
                              "FALL_THROUGH",
                              "ram:00102004"),
                          new InstructionSummary(
                              "ram:00102004",
                              2,
                              "JZ",
                              List.of("0x00102020"),
                              "CONDITIONAL_JUMP",
                              "ram:00102006")),
                      List.of(
                          new FlowEdge("ram:00102004", "ram:00102020", "CONDITIONAL_JUMP"),
                          new FlowEdge("ram:00102004", "ram:00102006", "FALL_THROUGH")));
              ScanProgress progress =
                  new ScanProgress(
                      ScanProgress.Kind.ADDRESS,
                      "ram:00102000",
                      "ram:00102030",
                      "ram:00102000",
                      "ram:00102000",
                      true,
                      ScanProgress.StopReason.COMPLETED,
                      2L);
              return Page.scanned(List.of(block), 100, null, progress);
            });

    ApiRegistry registry = registryWith(unused(FunctionService.class), listing, unused(ReferenceService.class));

    @SuppressWarnings("unchecked")
    Map<String, Object> result =
        (Map<String, Object>)
            registry.dispatch(
                "basic_block.list",
                Map.of(
                    "filter",
                        Map.of(
                            "selector", Map.of("kind", "function", "entry", "0x102000"),
                            "max_edges", 500),
                    "scan", Map.of("timeout_ms", 4000)));

    assertEquals(new FlowOverrideScope.FunctionScope("0x102000"), capturedScope.get());
    assertEquals(500, capturedMaxEdges.get());
    @SuppressWarnings("unchecked")
    List<Map<String, Object>> items = (List<Map<String, Object>>) result.get("items");
    assertEquals(1, items.size());
    assertEquals("CONDITIONAL_JUMP", items.getFirst().get("flow_type"));
    @SuppressWarnings("unchecked")
    List<Map<String, Object>> destinations =
        (List<Map<String, Object>>) items.getFirst().get("destinations");
    assertEquals("CONDITIONAL_JUMP", destinations.get(0).get("type"));
    assertEquals("FALL_THROUGH", destinations.get(1).get("type"));
  }

  @Test
  void referenceListAcceptsSelectorAndLegacySingleAddressFilters() throws Exception {
    AtomicReference<ReferenceQuery> captured = new AtomicReference<>();
    ReferenceService references =
        proxy(
            ReferenceService.class,
            (method, args) -> {
              assertEquals("listReferences", method);
              ReferenceQuery query = (ReferenceQuery) args[0];
              captured.set(query);
              ReferenceResource ref =
                  new ReferenceResource(
                      "ram:00102008", "ram:00101000", "UNCONDITIONAL_CALL", 0, true, "DEFAULT");
              ScanProgress progress =
                  new ScanProgress(
                      ScanProgress.Kind.ADDRESS,
                      "ram:00102000",
                      "ram:00102020",
                      "ram:00102008",
                      "ram:00102008",
                      true,
                      ScanProgress.StopReason.COMPLETED,
                      1L);
              return Page.scanned(List.of(ref), query.limit(), null, progress);
            });

    ApiRegistry registry =
        registryWith(unused(FunctionService.class), unused(ListingService.class), references);

    registry.dispatch(
        "reference.list",
        Map.of(
            "filter",
            Map.of(
                "direction", "from",
                "selector", Map.of("kind", "function", "entry", "0x102000"))));
    assertEquals(new FlowOverrideScope.FunctionScope("0x102000"), captured.get().selector());
    assertNull(captured.get().from());

    registry.dispatch(
        "reference.list",
        Map.of("filter", Map.of("direction", "to", "to", "0x101000")));
    assertNull(captured.get().selector());
    assertEquals("0x101000", captured.get().to());
    assertEquals(AddressScanOptions.DEFAULT_TIMEOUT_MS, captured.get().scan().timeoutMs());
  }

  private static ApiRegistry registryWith(
      FunctionService functions, ListingService listing, ReferenceService references) {
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
    TransactionRunner transaction =
        new TransactionRunner() {
          @Override
          public <T> T run(Operation<T> operation) {
            throw new AssertionError("read methods must not start a transaction");
          }
        };
    BridgeServices services =
        new BridgeServices(
            unused(ProgramService.class),
            unused(AddressService.class),
            unused(CommentService.class),
            references,
            unused(MemoryService.class),
            listing,
            functions,
            unused(GlobalVariableService.class),
            analysis,
            unused(DecompilationService.class),
            unused(SymbolService.class),
            unused(DataTypeService.class),
            transaction,
            "test-session");
    return new ApiRegistry(services, "test-session", Map::of, () -> {});
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
