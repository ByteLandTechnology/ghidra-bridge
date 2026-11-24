package app.byteland.ghidra.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.ScanProgress;
import app.byteland.ghidra.service.TransactionRunner;
import app.byteland.ghidra.service.address.AddressService;
import app.byteland.ghidra.service.analysis.AnalysisResource;
import app.byteland.ghidra.service.analysis.AnalysisService;
import app.byteland.ghidra.service.comment.CommentService;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.datatype.DataTypeService;
import app.byteland.ghidra.service.decompilation.DecompilationService;
import app.byteland.ghidra.service.function.FunctionService;
import app.byteland.ghidra.service.function.VariableStorageReference;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService;
import app.byteland.ghidra.service.listing.FlowOverrideValue;
import app.byteland.ghidra.service.listing.InstructionResource;
import app.byteland.ghidra.service.listing.ListingService;
import app.byteland.ghidra.service.memory.MemoryBlockResource;
import app.byteland.ghidra.service.memory.MemoryResource;
import app.byteland.ghidra.service.memory.MemoryService;
import app.byteland.ghidra.service.program.AddressSpaceResource;
import app.byteland.ghidra.service.program.ProgramService;
import app.byteland.ghidra.service.reference.ReferenceService;
import app.byteland.ghidra.service.symbol.SymbolResource;
import app.byteland.ghidra.service.symbol.SymbolService;
import java.lang.reflect.Proxy;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

class WireValuesTest {
  @Test
  void resourceNormalizesTypedRecordsAndOmitsNullComponents() {
    SymbolResource symbol =
        new SymbolResource(
            "42", "main", "0x00401000", "Global", "function", "user_defined", true, null);

    Map<String, Object> wire = WireValues.resource(symbol);

    assertEquals(
        Map.of(
            "id", "42",
            "name", "main",
            "address", "0x00401000",
            "namespace", "Global",
            "type", "function",
            "source_type", "user_defined",
            "primary", true),
        wire);
    assertFalse(wire.containsKey("demangled_name"));

    Instant startedAt = Instant.parse("2026-06-05T12:00:00Z");
    AnalysisResource analysis =
        new AnalysisResource(
            AnalysisResource.Kind.BRIDGE,
            AnalysisResource.Status.RUNNING,
            false,
            "task-1",
            startedAt,
            null,
            50.0,
            null,
            null);

    Map<String, Object> analysisWire = WireValues.resource(analysis);
    assertEquals("bridge", analysisWire.get("kind"));
    assertEquals("running", analysisWire.get("status"));
    assertEquals(false, analysisWire.get("analyzed"));
    assertEquals("task-1", analysisWire.get("task_id"));
    assertEquals("2026-06-05T12:00:00Z", analysisWire.get("started_at"));
    assertFalse(analysisWire.containsKey("finished_at"));
    assertEquals(50.0, analysisWire.get("progress"));
  }

  @Test
  void resourceAppliesWireKeyOverridesForAddressSpaceAndMemoryBlock() {
    AddressSpaceResource space =
        new AddressSpaceResource(
            "ram", AddressSpaceResource.Kind.RAM, 64, "0x0", "0xffffffffffffffff", true);

    Map<String, Object> spaceWire = WireValues.resource(space);
    assertEquals(
        Map.of(
            "name", "ram",
            "kind", "ram",
            "size", 64,
            "min_address", "0x0",
            "max_address", "0xffffffffffffffff",
            "default", true),
        spaceWire);
    assertFalse(spaceWire.containsKey("is_default"));

    MemoryBlockResource block =
        new MemoryBlockResource(
            ".mmio",
            "0x40000000",
            "0x40000fff",
            4096L,
            true,
            true,
            false,
            false,
            true,
            false,
            MemoryBlockResource.Kind.DEFAULT,
            null);

    Map<String, Object> blockWire = WireValues.resource(block);
    assertEquals(true, blockWire.get("volatile"));
    assertEquals("default", blockWire.get("kind"));
    assertFalse(blockWire.containsKey("is_volatile"));
    assertFalse(blockWire.containsKey("comment"));
  }

  @Test
  void normalizeSupportsSealedReferencesAndIterables() {
    DataTypeReference arrayOfPointers =
        DataTypeReference.arrayOf(DataTypeReference.pointerTo(DataTypeReference.named("char")), 8);
    assertEquals(
        Map.of(
            "kind",
            "array",
            "element",
            Map.of("kind", "pointer", "target", Map.of("kind", "named", "name", "char")),
            "count",
            8),
        WireValues.normalize(arrayOfPointers));
    assertEquals(
        Map.of("kind", "untyped_pointer"), WireValues.normalize(DataTypeReference.untypedPointer()));

    assertEquals(
        Map.of("kind", "register", "register", "RAX"),
        WireValues.normalize(VariableStorageReference.register("RAX")));
    assertEquals(
        Map.of("kind", "serialization", "serialization", "Stack[-0x10]:8"),
        WireValues.normalize(VariableStorageReference.serialization("Stack[-0x10]:8")));

    SymbolService.DemangleResult demangle =
        new SymbolService.DemangleResult(3, 1, List.of("_Zbad: unsupported"));
    assertEquals(
        Map.of("renamed", 3, "failed", 1, "failures", List.of("_Zbad: unsupported")),
        WireValues.resource(demangle));
  }

  @Test
  void listNormalizesPagesCursorsScanProgressAndRejectsNull() {
    SymbolResource first =
        new SymbolResource(
            "1", "entry", "0x00401000", "Global", "function", "analysis", true, null);

    Page<SymbolResource> singlePage = Page.of(List.of(first), 10, null);
    Map<String, Object> singleWire = WireValues.list(singlePage);
    assertEquals(List.of(WireValues.resource(first)), singleWire.get("items"));
    assertFalse(singleWire.containsKey("next_cursor"));
    assertFalse(singleWire.containsKey("scan"));

    ScanProgress progress =
        new ScanProgress(
            ScanProgress.Kind.ADDRESS,
            "0x00401000",
            "0x00402000",
            "0x00401000",
            "0x00401010",
            false,
            ScanProgress.StopReason.LIMIT,
            12L);
    Page<SymbolResource> scannedPage = Page.scanned(List.of(first), 1, "0x00401010", progress);
    Map<String, Object> scannedWire = WireValues.list(scannedPage);
    assertEquals(List.of(WireValues.resource(first)), scannedWire.get("items"));
    assertEquals("0x00401010", scannedWire.get("next_cursor"));
    assertEquals(
        Map.of(
            "kind", "address",
            "requested_start", "0x00401000",
            "requested_end", "0x00402000",
            "scanned_start", "0x00401000",
            "scanned_end", "0x00401010",
            "complete", false,
            "stop_reason", "limit",
            "elapsed_ms", 12L),
        scannedWire.get("scan"));

    assertThrows(IllegalArgumentException.class, () -> WireValues.list(null));
  }

  @Test
  void memoryResourceNormalizesThroughResourceAndMemoryReadDispatch() throws Exception {
    MemoryResource hexMemory =
        new MemoryResource(
            "0x00401000", new ByteSequence(ByteSequence.Encoding.HEX, "deadbeef", 4));
    assertEquals(
        Map.of(
            "address",
            "0x00401000",
            "bytes",
            Map.of("encoding", "hex", "data", "deadbeef", "length", 4)),
        WireValues.resource(hexMemory));

    MemoryResource base64Memory =
        new MemoryResource(
            "0x00401004", new ByteSequence(ByteSequence.Encoding.BASE64, "3q2+7w==", 4));
    assertEquals(
        Map.of(
            "address",
            "0x00401004",
            "bytes",
            Map.of("encoding", "base64", "data", "3q2+7w==", "length", 4)),
        WireValues.resource(base64Memory));

    MemoryService memoryService =
        proxy(
            MemoryService.class,
            (method, args) -> {
              assertEquals("readMemoryRange", method);
              return hexMemory;
            });
    AnalysisService analysisService =
        proxy(
            AnalysisService.class,
            (method, args) ->
                new AnalysisResource(
                    AnalysisResource.Kind.GHIDRA,
                    AnalysisResource.Status.IDLE,
                    true,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null));
    BridgeServices services =
        new BridgeServices(
            unused(ProgramService.class),
            unused(AddressService.class),
            unused(CommentService.class),
            unused(ReferenceService.class),
            memoryService,
            unused(ListingService.class),
            unused(FunctionService.class),
            unused(GlobalVariableService.class),
            analysisService,
            unused(DecompilationService.class),
            unused(SymbolService.class),
            unused(DataTypeService.class),
            unused(TransactionRunner.class),
            "demo");
    ApiRegistry registry = new ApiRegistry(services, "session-1", Map::of, () -> {});

    Object full =
        registry.dispatch("memory.read", Map.of("selector", Map.of("address", "0x00401000")));
    assertEquals(
        Map.of(
            "address",
            "0x00401000",
            "bytes",
            Map.of("encoding", "hex", "data", "deadbeef", "length", 4)),
        full);

    Object projected =
        registry.dispatch(
            "memory.read",
            Map.of(
                "selector",
                Map.of("address", "0x00401000"),
                "projection",
                Map.of("fields", List.of("bytes.data"))));
    assertEquals(
        Map.of("address", "0x00401000", "bytes", Map.of("data", "deadbeef")), projected);
  }

  @Test
  void registryListAndWriteListResultDispatchTypedPages() throws Exception {
    AddressSpaceResource ram =
        new AddressSpaceResource(
            "ram", AddressSpaceResource.Kind.RAM, 64, "0x0", "0xffffffffffffffff", true);
    ProgramService programService =
        proxy(
            ProgramService.class,
            (method, args) -> {
              assertEquals("getAddressSpaces", method);
              return Page.of(List.of(ram), 1, "ram");
            });
    InstructionResource patchedInstruction =
        new InstructionResource(
            "0x00401000",
            2,
            new ByteSequence(ByteSequence.Encoding.HEX, "ffe0", 2),
            "JMP",
            List.of("RAX"),
            FlowOverrideValue.CALL_RETURN,
            "unconditional_jump",
            "call_terminator",
            null);
    ListingService listingService =
        proxy(
            ListingService.class,
            (method, args) ->
                switch (method) {
                  case "setFlowOverrides" -> null;
                  case "getFlowOverrides" -> Page.of(List.of(patchedInstruction), 1000, null);
                  default -> throw new AssertionError("unexpected call: " + method);
                });
    AnalysisService analysisService =
        proxy(
            AnalysisService.class,
            (method, args) ->
                new AnalysisResource(
                    AnalysisResource.Kind.GHIDRA,
                    AnalysisResource.Status.IDLE,
                    true,
                    null,
                    null,
                    null,
                    null,
                    null,
                    null));
    TransactionRunner transactionRunner =
        new TransactionRunner() {
          @Override
          public <T> T run(Operation<T> operation) {
            try {
              return operation.execute();
            } catch (Exception exception) {
              throw new RuntimeException(exception);
            }
          }
        };
    BridgeServices services =
        new BridgeServices(
            programService,
            unused(AddressService.class),
            unused(CommentService.class),
            unused(ReferenceService.class),
            unused(MemoryService.class),
            listingService,
            unused(FunctionService.class),
            unused(GlobalVariableService.class),
            analysisService,
            unused(DecompilationService.class),
            unused(SymbolService.class),
            unused(DataTypeService.class),
            transactionRunner,
            "demo");
    ApiRegistry registry = new ApiRegistry(services, "session-1", Map::of, () -> {});

    @SuppressWarnings("unchecked")
    Map<String, Object> listResult =
        (Map<String, Object>)
            registry.dispatch("address_space.list", Map.of("page", Map.of("limit", 1)));
    assertEquals(List.of(WireValues.resource(ram)), listResult.get("items"));
    assertNotNull(listResult.get("next_cursor"));

    @SuppressWarnings("unchecked")
    Map<String, Object> patchResult =
        (Map<String, Object>)
            registry.dispatch(
                "flow_override.patch",
                Map.of(
                    "selector", Map.of("kind", "address", "address", "0x00401000"),
                    "patch", Map.of("flow_override", "call_return")));
    assertEquals(List.of(WireValues.resource(patchedInstruction)), patchResult.get("items"));
    assertFalse(patchResult.containsKey("next_cursor"));
  }

  @Test
  void mapNormalizationPreservesReceiptAndSessionEntriesWhileFilteringNulls() {
    assertEquals(Map.of("saved", true), WireValues.resource(Map.of("saved", true)));
    assertEquals(
        Map.of("start", "0x00401000", "length", 4),
        WireValues.resource(Map.of("start", "0x00401000", "length", 4)));

    Map<String, Object> session = new LinkedHashMap<>();
    session.put("id", "demo");
    session.put("status", "active");
    session.put("program_name", null);
    Map<String, Object> normalizedSession = WireValues.resource(session);
    assertEquals(Map.of("id", "demo", "status", "active"), normalizedSession);
    assertFalse(normalizedSession.containsKey("program_name"));

    Map<String, Object> raw = new LinkedHashMap<>();
    raw.put("camelKey", " intact ");
    raw.put("id", 7);
    raw.put("bytes", "deadbeef");
    raw.put("started_at", 12345L);
    raw.put("type", "CamelValue");
    Map<String, Object> passthrough = WireValues.resource(raw);
    assertEquals(" intact ", passthrough.get("camelKey"));
    assertEquals(7, passthrough.get("id"));
    assertEquals("deadbeef", passthrough.get("bytes"));
    assertEquals(12345L, passthrough.get("started_at"));
    assertEquals("CamelValue", passthrough.get("type"));
  }

  @Test
  void restrictKeepsSelectedRootFields() {
    Map<String, Object> value = new LinkedHashMap<>();
    value.put("address", "0x00401000");
    value.put("bytes", Map.of("encoding", "hex", "data", "90", "length", 1));
    value.put("extra", "ignored");

    assertEquals(
        Map.of(
            "address",
            "0x00401000",
            "bytes",
            Map.of("encoding", "hex", "data", "90", "length", 1)),
        WireValues.restrict(value, Set.of("address", "bytes.data")));
  }

  private interface MethodHandler {
    Object invoke(String method, Object[] args);
  }

  private static <T> T unused(Class<T> type) {
    return proxy(
        type,
        (method, args) -> {
          throw new AssertionError("unexpected call: " + method);
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
