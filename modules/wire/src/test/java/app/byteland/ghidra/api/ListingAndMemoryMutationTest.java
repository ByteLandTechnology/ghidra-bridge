package app.byteland.ghidra.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.TransactionRunner;
import app.byteland.ghidra.service.address.AddressResource;
import app.byteland.ghidra.service.address.AddressService;
import app.byteland.ghidra.service.analysis.AnalysisResource;
import app.byteland.ghidra.service.analysis.AnalysisService;
import app.byteland.ghidra.service.comment.CommentService;
import app.byteland.ghidra.service.datatype.DataTypeService;
import app.byteland.ghidra.service.decompilation.DecompilationService;
import app.byteland.ghidra.service.function.FunctionService;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService;
import app.byteland.ghidra.service.listing.ClearedCodeUnitsResource;
import app.byteland.ghidra.service.listing.FlowOverrideValue;
import app.byteland.ghidra.service.listing.InstructionResource;
import app.byteland.ghidra.service.listing.ListingScope;
import app.byteland.ghidra.service.listing.ListingService;
import app.byteland.ghidra.service.memory.MemoryService;
import app.byteland.ghidra.service.program.ProgramService;
import app.byteland.ghidra.service.reference.ReferenceService;
import app.byteland.ghidra.service.symbol.SymbolService;
import java.lang.reflect.Proxy;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class ListingAndMemoryMutationTest {
  @Test
  void listingAndMemoryMutationsValidateDispatchAndRespectAnalysisGuard() throws Exception {
    AtomicReference<String> invokedMethod = new AtomicReference<>();
    AtomicReference<List<Object>> arguments = new AtomicReference<>();
    AtomicInteger transactions = new AtomicInteger();
    AtomicBoolean analysisRunning = new AtomicBoolean(false);

    ListingService listing =
        proxy(
            ListingService.class,
            (method, args) -> {
              invokedMethod.set(method);
              arguments.set(Arrays.asList(args));
              return switch (method) {
                case "assembleInstructions" -> {
                  if ("0xdead".equals(args[0])) {
                    throw new IllegalArgumentException("address is not in initialized memory");
                  }
                  yield List.of(
                      new InstructionResource(
                          "ram:00401000",
                          2,
                          new ByteSequence(ByteSequence.Encoding.HEX, "31c0", 2),
                          "XOR",
                          List.of("EAX", "EAX"),
                          FlowOverrideValue.NONE,
                          "FALL_THROUGH",
                          "FALL_THROUGH",
                          "ram:00401002"),
                      new InstructionResource(
                          "ram:00401002",
                          1,
                          new ByteSequence(ByteSequence.Encoding.HEX, "90", 1),
                          "NOP",
                          List.of(),
                          FlowOverrideValue.NONE,
                          "FALL_THROUGH",
                          "FALL_THROUGH",
                          "ram:00401003"));
                }
                case "disassemble" ->
                    List.of(
                        new InstructionResource(
                            "ram:00401010",
                            1,
                            new ByteSequence(ByteSequence.Encoding.HEX, "c3", 1),
                            "RET",
                            List.of(),
                            FlowOverrideValue.NONE,
                            "TERMINATOR",
                            "TERMINATOR",
                            null));
                case "clearCodeUnits" ->
                    new ClearedCodeUnitsResource("ram:00401000", "ram:00401004", 5L);
                default -> throw new AssertionError(method);
              };
            });

    MemoryService memory =
        proxy(
            MemoryService.class,
            (method, args) -> {
              invokedMethod.set(method);
              arguments.set(Arrays.asList(args));
              assertEquals("patchMemory", method);
              return null;
            });

    AddressService addresses =
        proxy(
            AddressService.class,
            (method, args) ->
                new AddressResource("ram:00401000", true, true, null, null, null, null));

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

    TransactionRunner transaction =
        new TransactionRunner() {
          @Override
          public <T> T run(Operation<T> operation) {
            transactions.incrementAndGet();
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
            addresses,
            unused(CommentService.class),
            unused(ReferenceService.class),
            memory,
            listing,
            unused(FunctionService.class),
            unused(GlobalVariableService.class),
            analysis,
            unused(DecompilationService.class),
            unused(SymbolService.class),
            unused(DataTypeService.class),
            transaction,
            "test");
    ApiRegistry registry = new ApiRegistry(services, "test", Map::of, () -> {});

    @SuppressWarnings("unchecked")
    Map<String, Object> assembled =
        (Map<String, Object>)
            registry.dispatch(
                "instruction.assemble",
                Map.of(
                    "selector", Map.of("address", "0x401000"),
                    "instructions", List.of("xor eax, eax"),
                    "pad_nop", true));
    assertEquals("assembleInstructions", invokedMethod.get());
    assertEquals(List.of("0x401000", List.of("xor eax, eax"), true), arguments.get());
    assertEquals(2, ((List<?>) assembled.get("items")).size());
    assertEquals(1, transactions.get());
    assertTrue(registry.method("instruction.assemble").effects().requiresTransaction());
    assertTrue(registry.method("instruction.assemble").effects().destructive());

    @SuppressWarnings("unchecked")
    Map<String, Object> disassembled =
        (Map<String, Object>)
            registry.dispatch(
                "instruction.disassemble",
                Map.of(
                    "selector", Map.of("kind", "range", "start", "0x401010", "end", "0x401014"),
                    "follow_flow", false));
    assertEquals("disassemble", invokedMethod.get());
    assertEquals(
        List.of(new ListingScope.RangeScope("0x401010", "0x401014"), false), arguments.get());
    assertEquals(1, ((List<?>) disassembled.get("items")).size());
    assertEquals(2, transactions.get());
    assertFalse(registry.method("instruction.disassemble").effects().destructive());

    @SuppressWarnings("unchecked")
    Map<String, Object> cleared =
        (Map<String, Object>)
            registry.dispatch(
                "code_unit.clear",
                Map.of(
                    "selector", Map.of("kind", "address", "address", "0x401000"),
                    "clear_context", true));
    assertEquals("clearCodeUnits", invokedMethod.get());
    assertEquals(List.of(new ListingScope.AddressScope("0x401000"), true), arguments.get());
    assertEquals(
        Map.of("start", "ram:00401000", "end", "ram:00401004", "length", 5L), cleared);
    assertEquals(3, transactions.get());

    @SuppressWarnings("unchecked")
    Map<String, Object> written =
        (Map<String, Object>)
            registry.dispatch(
                "memory.write",
                Map.of(
                    "selector", Map.of("address", "0x401000"),
                    "patch",
                        Map.of(
                            "bytes", Map.of("encoding", "hex", "data", "90c3", "length", 2),
                            "clear_existing", true,
                            "disassemble", true)));
    assertEquals("patchMemory", invokedMethod.get());
    assertEquals(
        List.of(
            "0x401000",
            new ByteSequence(ByteSequence.Encoding.HEX, "90c3", 2),
            true,
            true),
        arguments.get());
    assertEquals(Map.of("start", "ram:00401000", "length", 2), written);
    assertEquals(4, transactions.get());

    // Domain validation errors map to HTTP 400 through ApiFailures.
    IllegalArgumentException badAddr =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                registry.dispatch(
                    "instruction.assemble",
                    Map.of(
                        "selector", Map.of("address", "0xdead"),
                        "instructions", List.of("nop"))));
    assertEquals(400, ApiFailures.normalize(badAddr).status());

    // Schema validation rejects empty instructions array.
    assertThrows(
        ApiException.class,
        () ->
            registry.dispatch(
                "instruction.assemble",
                Map.of("selector", Map.of("address", "0x401000"), "instructions", List.of())));

    // Analysis guard rejects all code-unit and memory writes with 409 analysis_in_progress.
    analysisRunning.set(true);
    assertAnalysisConflict(
        registry,
        "instruction.assemble",
        Map.of("selector", Map.of("address", "0x401000"), "instructions", List.of("nop")));
    assertAnalysisConflict(
        registry,
        "instruction.disassemble",
        Map.of("selector", Map.of("kind", "address", "address", "0x401000")));
    assertAnalysisConflict(
        registry,
        "code_unit.clear",
        Map.of("selector", Map.of("kind", "address", "address", "0x401000")));
    assertAnalysisConflict(
        registry,
        "memory.write",
        Map.of(
            "selector", Map.of("address", "0x401000"),
            "patch", Map.of("bytes", Map.of("encoding", "hex", "data", "90", "length", 1))));
  }

  private static void assertAnalysisConflict(
      ApiRegistry registry, String method, Map<String, Object> params) {
    ApiException conflict =
        assertThrows(ApiException.class, () -> registry.dispatch(method, params));
    assertEquals(409, conflict.error().status());
    assertEquals("analysis_in_progress", conflict.error().code());
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
