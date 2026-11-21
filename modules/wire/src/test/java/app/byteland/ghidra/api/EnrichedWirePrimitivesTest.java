package app.byteland.ghidra.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import app.byteland.ghidra.service.AmbiguousTargetException;
import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.ScanProgress;
import app.byteland.ghidra.service.TransactionRunner;
import app.byteland.ghidra.service.address.AddressService;
import app.byteland.ghidra.service.analysis.AnalysisService;
import app.byteland.ghidra.service.comment.CommentService;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.datatype.DataTypeResource;
import app.byteland.ghidra.service.datatype.DataTypeSelector;
import app.byteland.ghidra.service.datatype.DataTypeService;
import app.byteland.ghidra.service.decompilation.DecompilationResource;
import app.byteland.ghidra.service.decompilation.DecompilationService;
import app.byteland.ghidra.service.function.FunctionCallResource;
import app.byteland.ghidra.service.function.FunctionResource;
import app.byteland.ghidra.service.function.FunctionSelector;
import app.byteland.ghidra.service.function.FunctionService;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService;
import app.byteland.ghidra.service.listing.DataUnitResource;
import app.byteland.ghidra.service.listing.FlowOverrideValue;
import app.byteland.ghidra.service.listing.InstructionResource;
import app.byteland.ghidra.service.listing.ListingService;
import app.byteland.ghidra.service.memory.MemorySearchMatchResource;
import app.byteland.ghidra.service.memory.MemoryService;
import app.byteland.ghidra.service.program.ProgramService;
import app.byteland.ghidra.service.reference.ReferenceService;
import app.byteland.ghidra.service.symbol.SymbolService;
import java.lang.reflect.Proxy;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class EnrichedWirePrimitivesTest {
  private static final ScanProgress COMPLETED_SCAN =
      new ScanProgress(
          ScanProgress.Kind.ADDRESS,
          "ram:00100000",
          "ram:00100100",
          "ram:00100000",
          "ram:00100100",
          true,
          ScanProgress.StopReason.COMPLETED,
          2L);

  @Test
  void memorySearchDispatchesBoundedQueriesAndProjectsMatches() throws Exception {
    AtomicReference<MemoryService.MemorySearchQuery> captured = new AtomicReference<>();
    MemoryService memory =
        proxy(
            MemoryService.class,
            (method, args) -> {
              assertEquals("searchMemory", method);
              MemoryService.MemorySearchQuery query = (MemoryService.MemorySearchQuery) args[0];
              captured.set(query);
              MemorySearchMatchResource match =
                  new MemorySearchMatchResource(
                      "ram:00100020",
                      3,
                      new ByteSequence(ByteSequence.Encoding.HEX, "488bc7", 3),
                      ".text");
              return Page.scanned(List.of(match), query.limit(), null, COMPLETED_SCAN);
            });
    ApiRegistry registry = registryWith(memory, null, null, null, null);

    Map<?, ?> response =
        (Map<?, ?>)
            registry.dispatch(
                "memory.search",
                Map.of(
                    "filter", Map.of("pattern", "48 8B ??"),
                    "scan",
                        Map.of(
                            "range",
                            Map.of("start", "0x100000", "end", "0x100100"),
                            "timeout_ms",
                            1500),
                    "page", Map.of("limit", 25)));

    assertEquals(new MemoryService.HexPattern("48 8B ??"), captured.get().target());
    assertEquals("0x100000", captured.get().scan().start());
    assertEquals("0x100100", captured.get().scan().end());
    assertEquals(1500, captured.get().scan().timeoutMs());
    assertEquals(25, captured.get().limit());
    List<?> items = (List<?>) response.get("items");
    assertEquals(1, items.size());
    assertEquals("ram:00100020", ((Map<?, ?>) items.getFirst()).get("address"));
    assertEquals(".text", ((Map<?, ?>) items.getFirst()).get("block_name"));

    // Rejects mutually exclusive search modes or missing search mode.
    assertThrows(
        ApiException.class,
        () ->
            registry.dispatch(
                "memory.search",
                Map.of(
                    "filter", Map.of("pattern", "90", "text", "nop"),
                    "scan", Map.of("timeout_ms", 500))));
    assertThrows(
        ApiException.class,
        () ->
            registry.dispatch(
                "memory.search", Map.of("filter", Map.of(), "scan", Map.of("timeout_ms", 500))));
  }

  @Test
  void listingFiltersAndInstructionFlowsAreWired() throws Exception {
    AtomicReference<ListingService.DataUnitListQuery> dataQuery = new AtomicReference<>();
    AtomicReference<ListingService.InstructionListQuery> instrQuery = new AtomicReference<>();
    ListingService listing =
        proxy(
            ListingService.class,
            (method, args) -> {
              if (method.equals("listDataUnits")) {
                ListingService.DataUnitListQuery q = (ListingService.DataUnitListQuery) args[0];
                dataQuery.set(q);
                DataUnitResource unit =
                    new DataUnitResource(
                        "ram:00200000",
                        6,
                        DataTypeReference.named("string"),
                        "hello",
                        "\"hello\"",
                        new ByteSequence(ByteSequence.Encoding.HEX, "68656c6c6f00", 6));
                return Page.scanned(List.of(unit), q.limit(), null, COMPLETED_SCAN);
              }
              assertEquals("listInstructions", method);
              ListingService.InstructionListQuery q = (ListingService.InstructionListQuery) args[0];
              instrQuery.set(q);
              InstructionResource instr =
                  new InstructionResource(
                      "ram:00100010",
                      2,
                      new ByteSequence(ByteSequence.Encoding.HEX, "7408", 2),
                      "JZ",
                      List.of("0x0010001a"),
                      FlowOverrideValue.NONE,
                      "CONDITIONAL_JUMP",
                      "CONDITIONAL_JUMP",
                      "ram:00100012",
                      List.of("ram:0010001a"));
              return Page.scanned(List.of(instr), q.limit(), null, COMPLETED_SCAN);
            });
    ApiRegistry registry = registryWith(null, listing, null, null, null);

    registry.dispatch(
        "data_unit.list",
        Map.of(
            "filter",
                Map.of(
                    "data_type", "string",
                    "string_only", true,
                    "value_contains", "hel",
                    "case_sensitive", true),
            "scan", Map.of("timeout_ms", 1000)));
    assertEquals("string", dataQuery.get().dataType());
    assertEquals(true, dataQuery.get().stringOnly());
    assertEquals("hel", dataQuery.get().valueContains());
    assertEquals(true, dataQuery.get().caseSensitive());

    Map<?, ?> instrResult =
        (Map<?, ?>)
            registry.dispatch(
                "instruction.list",
                Map.of(
                    "filter",
                        Map.of(
                            "mnemonic", "JZ",
                            "flow_type", "CONDITIONAL_JUMP",
                            "function", "0x100000"),
                    "scan", Map.of("timeout_ms", 1000)));
    assertEquals("JZ", instrQuery.get().mnemonic());
    assertEquals("CONDITIONAL_JUMP", instrQuery.get().flowType());
    assertEquals("0x100000", instrQuery.get().function());
    Map<?, ?> item = (Map<?, ?>) ((List<?>) instrResult.get("items")).getFirst();
    assertEquals(List.of("ram:0010001a"), item.get("flows"));
  }

  @Test
  void functionAndDecompilationSelectorsBodyRangesAndCallSitesAreWired() throws Exception {
    AtomicReference<FunctionSelector> fnSelector = new AtomicReference<>();
    AtomicReference<FunctionSelector> decompSelector = new AtomicReference<>();
    FunctionService functions =
        proxy(
            FunctionService.class,
            (method, args) -> {
              if (method.equals("getCallers")) {
                return Page.of(
                    List.of(
                        new FunctionCallResource(
                            "ram:00100000",
                            "caller",
                            "ram:00100024",
                            FunctionCallResource.Direction.CALLERS,
                            "Global",
                            null),
                        new FunctionCallResource(
                            "ram:00100000",
                            "caller",
                            "ram:00100014",
                            FunctionCallResource.Direction.CALLERS,
                            "Global",
                            null)),
                    100,
                    null);
              }
              assertEquals("getFunction", method);
              FunctionSelector sel = (FunctionSelector) args[0];
              fnSelector.set(sel);
              if (sel instanceof FunctionSelector.Symbol sym && sym.name().equals("dup")) {
                throw new AmbiguousTargetException(
                    "ambiguous_symbol",
                    "ambiguous function symbol: dup",
                    "selector.symbol",
                    List.of("A::dup @ ram:00100000", "B::dup @ ram:00100200"));
              }
              return new FunctionResource(
                  "ram:00100000",
                  "split_fn",
                  "Global",
                  new FunctionResource.Body(
                      "ram:00100000",
                      "ram:00100420",
                      32L,
                      List.of(
                          new FunctionResource.AddressRange("ram:00100000", "ram:0010000f"),
                          new FunctionResource.AddressRange("ram:00100410", "ram:00100420"))),
                  null,
                  null,
                  null,
                  0,
                  null,
                  null,
                  null,
                  null,
                  false,
                  false,
                  false,
                  false,
                  null,
                  false,
                  false,
                  null,
                  null,
                  null);
            });
    DecompilationService decompilation =
        proxy(
            DecompilationService.class,
            (method, args) -> {
              assertEquals("decompileFunction", method);
              decompSelector.set((FunctionSelector) args[0]);
              return new DecompilationResource(
                  "ram:00100000",
                  "split_fn",
                  DecompilationResource.Format.TEXT,
                  true,
                  5L,
                  "void split_fn(void) {}\n",
                  null,
                  null,
                  null,
                  null,
                  List.of());
            });
    ApiRegistry registry = registryWith(null, null, functions, decompilation, null);

    Map<?, ?> byContaining =
        (Map<?, ?>)
            registry.dispatch("function.get", Map.of("selector", Map.of("address", "0x100418")));
    assertEquals(new FunctionSelector.Containing("0x100418"), fnSelector.get());
    Map<?, ?> body = (Map<?, ?>) byContaining.get("body");
    List<?> ranges = (List<?>) body.get("ranges");
    assertEquals(2, ranges.size());
    assertEquals("ram:00100410", ((Map<?, ?>) ranges.get(1)).get("start"));

    registry.dispatch(
        "decompilation.get",
        Map.of("selector", Map.of("name", "split_fn", "namespace", "Global")));
    assertEquals(new FunctionSelector.Symbol("split_fn", "Global"), decompSelector.get());

    // Ambiguous bare symbol maps to HTTP 409 ambiguous_target with candidate details.
    Exception conflict =
        assertThrows(
            AmbiguousTargetException.class,
            () -> registry.dispatch("function.get", Map.of("selector", Map.of("symbol", "dup"))));
    var normalized = ApiFailures.normalize(conflict);
    assertEquals(409, normalized.status());
    assertEquals("ambiguous_symbol", normalized.error().code());
    assertEquals("/selector/symbol", normalized.error().target());
    assertEquals(2, ((List<?>) normalized.error().details().get("candidates")).size());

    // Call list sorts by (entry, call_site) and retains call_site under minimal projection.
    Map<?, ?> callPage =
        (Map<?, ?>)
            registry.dispatch(
                "function_call.list",
                Map.of(
                    "filter", Map.of("entry", "0x100500", "direction", "callers"),
                    "projection", Map.of("fields", List.of("entry"))));
    List<?> calls = (List<?>) callPage.get("items");
    assertEquals("ram:00100014", ((Map<?, ?>) calls.get(0)).get("call_site"));
    assertEquals("ram:00100024", ((Map<?, ?>) calls.get(1)).get("call_site"));
  }

  @Test
  void dataTypeBareNameLookupAndCompositeDetailFlagAreWired() throws Exception {
    AtomicReference<DataTypeSelector> dtSelector = new AtomicReference<>();
    AtomicReference<Boolean> includeDetails = new AtomicReference<>();
    DataTypeService dataTypes =
        proxy(
            DataTypeService.class,
            (method, args) -> {
              if (method.equals("getDataType")) {
                DataTypeSelector sel = (DataTypeSelector) args[0];
                dtSelector.set(sel);
                return new DataTypeResource(
                    "/types/Packet",
                    "Packet",
                    "/types",
                    DataTypeResource.Kind.STRUCT,
                    8,
                    null,
                    8,
                    List.of(),
                    null,
                    null,
                    null);
              }
              assertEquals("searchDataTypes", method);
              includeDetails.set((Boolean) args[3]);
              return Page.of(
                  List.of(
                      new DataTypeResource(
                          "/types/Packet",
                          "Packet",
                          "/types",
                          DataTypeResource.Kind.STRUCT,
                          8,
                          null,
                          8,
                          List.of(),
                          null,
                          null,
                          null)),
                  50,
                  null);
            });
    ApiRegistry registry = registryWith(null, null, null, null, dataTypes);

    registry.dispatch(
        "data_type.get",
        Map.of("selector", Map.of("name", "Packet", "category_path", "/types")));
    assertEquals(new DataTypeSelector.ByName("Packet", "/types"), dtSelector.get());

    registry.dispatch(
        "data_type.list",
        Map.of("filter", Map.of("query", "Packet", "include_details", true)));
    assertEquals(Boolean.TRUE, includeDetails.get());

    // Requesting fields in projection also enables composite details automatically.
    registry.dispatch(
        "data_type.list",
        Map.of(
            "filter", Map.of("query", "Packet"),
            "projection", Map.of("fields", List.of("path", "fields"))));
    assertEquals(Boolean.TRUE, includeDetails.get());
  }

  private static ApiRegistry registryWith(
      MemoryService memory,
      ListingService listing,
      FunctionService functions,
      DecompilationService decompilation,
      DataTypeService dataTypes) {
    TransactionRunner tx =
        new TransactionRunner() {
          @Override
          public <T> T run(Operation<T> operation) {
            throw new AssertionError("unexpected transaction");
          }
        };
    BridgeServices services =
        new BridgeServices(
            unused(ProgramService.class),
            unused(AddressService.class),
            unused(CommentService.class),
            unused(ReferenceService.class),
            memory != null ? memory : unused(MemoryService.class),
            listing != null ? listing : unused(ListingService.class),
            functions != null ? functions : unused(FunctionService.class),
            unused(GlobalVariableService.class),
            unused(AnalysisService.class),
            decompilation != null ? decompilation : unused(DecompilationService.class),
            unused(SymbolService.class),
            dataTypes != null ? dataTypes : unused(DataTypeService.class),
            tx,
            "test");
    return new ApiRegistry(services, "test", Map::of, () -> {});
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
