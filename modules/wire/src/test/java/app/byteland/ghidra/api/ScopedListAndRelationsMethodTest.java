package app.byteland.ghidra.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.ScanProgress;
import app.byteland.ghidra.service.TransactionRunner;
import app.byteland.ghidra.service.address.AddressResource;
import app.byteland.ghidra.service.address.AddressService;
import app.byteland.ghidra.service.analysis.AnalysisResource;
import app.byteland.ghidra.service.analysis.AnalysisService;
import app.byteland.ghidra.service.comment.CommentService;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.datatype.DataTypeService;
import app.byteland.ghidra.service.decompilation.DecompilationService;
import app.byteland.ghidra.service.function.FunctionCallResource;
import app.byteland.ghidra.service.function.FunctionService;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService;
import app.byteland.ghidra.service.listing.CodeUnitResource;
import app.byteland.ghidra.service.listing.FlowOverrideScope;
import app.byteland.ghidra.service.listing.FlowOverrideValue;
import app.byteland.ghidra.service.listing.InstructionResource;
import app.byteland.ghidra.service.listing.ListingService;
import app.byteland.ghidra.service.memory.MemoryService;
import app.byteland.ghidra.service.program.ProgramService;
import app.byteland.ghidra.service.reference.ReferenceResource;
import app.byteland.ghidra.service.reference.ReferenceService;
import app.byteland.ghidra.service.symbol.SymbolService;
import java.lang.reflect.Proxy;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class ScopedListAndRelationsMethodTest {
  @Test
  @SuppressWarnings("unchecked")
  void referenceListAcceptsScanAndSelectorAndProjectsFunctionSummaries() throws Exception {
    AtomicReference<FlowOverrideScope> capturedScope = new AtomicReference<>();
    AtomicReference<AddressScanOptions> capturedScan = new AtomicReference<>();
    ReferenceService references =
        (fromRaw, toRaw, type, direction, scope, scan, limit, cursor) -> {
          capturedScope.set(scope);
          capturedScan.set(scan);
          assertEquals("from", direction);
          assertEquals(50, limit);
          ReferenceResource item =
              new ReferenceResource(
                  "ram:00401010",
                  "ram:00402000",
                  "UNCONDITIONAL_CALL",
                  0,
                  true,
                  "DEFAULT",
                  new AddressResource.FunctionSummary("ram:00401000", "caller_fn"),
                  new AddressResource.FunctionSummary("ram:00402000", "callee_fn"));
          ScanProgress progress =
              new ScanProgress(
                  ScanProgress.Kind.ADDRESS,
                  "ram:00401000",
                  "ram:00401040",
                  "ram:00401010",
                  "ram:00401010",
                  true,
                  ScanProgress.StopReason.COMPLETED,
                  3L);
          return Page.scanned(List.of(item), limit, null, progress);
        };
    ApiRegistry registry = registryWith(references, unused(ListingService.class), unused(FunctionService.class));

    Map<String, Object> response =
        (Map<String, Object>)
            registry.dispatch(
                "reference.list",
                Map.of(
                    "filter",
                        Map.of(
                            "direction",
                            "from",
                            "selector",
                            Map.of("kind", "function", "entry", "0x401000")),
                    "scan",
                        Map.of(
                            "range", Map.of("start", "0x401000", "end", "0x401040"),
                            "timeout_ms", 5000),
                    "page", Map.of("limit", 50)));

    assertEquals(new FlowOverrideScope.FunctionScope("0x401000"), capturedScope.get());
    assertEquals(new AddressScanOptions("0x401000", "0x401040", 5000), capturedScan.get());
    List<Map<String, Object>> items = (List<Map<String, Object>>) response.get("items");
    assertEquals(1, items.size());
    assertEquals(
        Map.of("entry", "ram:00401000", "name", "caller_fn"), items.getFirst().get("from_function"));
    assertEquals(
        Map.of("entry", "ram:00402000", "name", "callee_fn"), items.getFirst().get("to_function"));
    Map<String, Object> scanMeta = (Map<String, Object>) response.get("scan");
    assertEquals(true, scanMeta.get("complete"));
    assertEquals("completed", scanMeta.get("stop_reason"));
  }

  @Test
  @SuppressWarnings("unchecked")
  void referenceListSupportsSingleAnchorWithoutExplicitDirection() throws Exception {
    ReferenceService references =
        (fromRaw, toRaw, type, direction, scope, scan, limit, cursor) -> {
          assertEquals("0x402000", toRaw);
          ReferenceResource item =
              new ReferenceResource(
                  "ram:00401010", "ram:00402000", "DATA", 0, true, "DEFAULT", null, null);
          ScanProgress progress =
              new ScanProgress(
                  ScanProgress.Kind.ADDRESS,
                  "ram:00402000",
                  "ram:00402000",
                  "ram:00402000",
                  "ram:00402000",
                  false,
                  ScanProgress.StopReason.TIMEOUT,
                  100L);
          return Page.scanned(List.of(item), limit, "cursor-1", progress);
        };
    ApiRegistry registry = registryWith(references, unused(ListingService.class), unused(FunctionService.class));

    Map<String, Object> response =
        (Map<String, Object>)
            registry.dispatch(
                "reference.list",
                Map.of(
                    "filter", Map.of("to", "0x402000"),
                    "scan", Map.of("timeout_ms", 100)));

    List<Map<String, Object>> items = (List<Map<String, Object>>) response.get("items");
    assertEquals(1, items.size());
    assertFalse(items.getFirst().containsKey("from_function"));
    assertFalse(items.getFirst().containsKey("to_function"));
    assertTrue(response.containsKey("next_cursor"));
    Map<String, Object> scanMeta = (Map<String, Object>) response.get("scan");
    assertEquals("timeout", scanMeta.get("stop_reason"));
  }

  @Test
  @SuppressWarnings("unchecked")
  void instructionListAcceptsFunctionSelectorAndLegacyRange() throws Exception {
    AtomicReference<FlowOverrideScope> capturedScope = new AtomicReference<>();
    ListingService listing =
        proxy(
            ListingService.class,
            (method, args) -> {
              assertEquals("listInstructions", method);
              capturedScope.set((FlowOverrideScope) args[0]);
              InstructionResource instr =
                  new InstructionResource(
                      "ram:00401000",
                      1,
                      new ByteSequence(ByteSequence.Encoding.HEX, "c3", 1),
                      "RET",
                      List.of(),
                      FlowOverrideValue.NONE,
                      "TERMINATOR",
                      "TERMINATOR",
                      null);
              ScanProgress progress =
                  new ScanProgress(
                      ScanProgress.Kind.ADDRESS,
                      "ram:00401000",
                      "ram:00409000",
                      "ram:00401000",
                      "ram:00401000",
                      true,
                      ScanProgress.StopReason.COMPLETED,
                      1L);
              return Page.scanned(List.of(instr), (Integer) args[2], null, progress);
            });
    ApiRegistry registry = registryWith(unused(ReferenceService.class), listing, unused(FunctionService.class));

    Map<String, Object> response =
        (Map<String, Object>)
            registry.dispatch(
                "instruction.list",
                Map.of(
                    "filter",
                    Map.of("selector", Map.of("kind", "function", "entry", "0x401000"))));

    assertEquals(new FlowOverrideScope.FunctionScope("0x401000"), capturedScope.get());
    List<Map<String, Object>> items = (List<Map<String, Object>>) response.get("items");
    assertEquals(1, items.size());
    assertEquals("RET", items.getFirst().get("mnemonic"));

    assertThrows(
        ApiException.class,
        () ->
            registry.dispatch(
                "instruction.list",
                Map.of("filter", Map.of("selector", Map.of("kind", "unknown")))));
  }

  @Test
  @SuppressWarnings("unchecked")
  void codeUnitListEmitsValueAndRepresentationOnlyWhenPresent() throws Exception {
    ListingService listing =
        proxy(
            ListingService.class,
            (method, args) -> {
              assertEquals("listCodeUnits", method);
              CodeUnitResource defined =
                  new CodeUnitResource(
                      "ram:00403000",
                      CodeUnitResource.Kind.DATA,
                      6,
                      new ByteSequence(ByteSequence.Encoding.HEX, "68656c6c6f00", 6),
                      "ds \"hello\"",
                      null,
                      null,
                      DataTypeReference.named("/string"),
                      "hello",
                      "\"hello\"");
              CodeUnitResource undefined =
                  new CodeUnitResource(
                      "ram:00403006",
                      CodeUnitResource.Kind.UNDEFINED,
                      1,
                      new ByteSequence(ByteSequence.Encoding.HEX, "00", 1),
                      "?? 00h",
                      null,
                      null,
                      DataTypeReference.named("/undefined"),
                      null,
                      null);
              ScanProgress progress =
                  new ScanProgress(
                      ScanProgress.Kind.ADDRESS,
                      "ram:00403000",
                      "ram:00403006",
                      "ram:00403000",
                      "ram:00403006",
                      true,
                      ScanProgress.StopReason.COMPLETED,
                      1L);
              return Page.scanned(List.of(defined, undefined), (Integer) args[1], null, progress);
            });
    ApiRegistry registry = registryWith(unused(ReferenceService.class), listing, unused(FunctionService.class));

    Map<String, Object> response =
        (Map<String, Object>) registry.dispatch("code_unit.list", Map.of());
    List<Map<String, Object>> items = (List<Map<String, Object>>) response.get("items");
    assertEquals(2, items.size());
    assertEquals("hello", items.get(0).get("value"));
    assertEquals("\"hello\"", items.get(0).get("representation"));
    assertFalse(items.get(1).containsKey("value"));
    assertFalse(items.get(1).containsKey("representation"));
  }

  @Test
  @SuppressWarnings("unchecked")
  void functionCallListPreservesMultipleCallSitesInDeterministicOrder() throws Exception {
    FunctionService functions =
        proxy(
            FunctionService.class,
            (method, args) -> {
              assertEquals("getCallees", method);
              List<FunctionCallResource> edges =
                  List.of(
                      new FunctionCallResource(
                          "ram:00402000",
                          "helper",
                          "ram:00401008",
                          FunctionCallResource.Direction.CALLEES,
                          "Global",
                          null),
                      new FunctionCallResource(
                          "ram:00402000",
                          "helper",
                          "ram:00401020",
                          FunctionCallResource.Direction.CALLEES,
                          "Global",
                          null));
              return Page.of(edges, (Integer) args[1], null);
            });
    ApiRegistry registry = registryWith(unused(ReferenceService.class), unused(ListingService.class), functions);

    Map<String, Object> response =
        (Map<String, Object>)
            registry.dispatch(
                "function_call.list",
                Map.of("filter", Map.of("entry", "0x401000", "direction", "callees")));
    List<Map<String, Object>> items = (List<Map<String, Object>>) response.get("items");
    assertEquals(2, items.size());
    assertEquals("ram:00401008", items.get(0).get("call_site"));
    assertEquals("ram:00401020", items.get(1).get("call_site"));
  }

  private static ApiRegistry registryWith(
      ReferenceService references, ListingService listing, FunctionService functions) {
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
            try {
              return operation.execute();
            } catch (RuntimeException ex) {
              throw ex;
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
