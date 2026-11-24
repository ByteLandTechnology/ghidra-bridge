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
import app.byteland.ghidra.service.listing.AddressOrRangeScope;
import app.byteland.ghidra.service.listing.CodeUnitClearReceipt;
import app.byteland.ghidra.service.listing.FlowOverrideValue;
import app.byteland.ghidra.service.listing.InstructionResource;
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
  void assembleDisassembleClearAndMemoryWriteValidateInputsAndTransactions() throws Exception {
    AtomicReference<String> calledMethod = new AtomicReference<>();
    AtomicReference<List<Object>> calledArgs = new AtomicReference<>();
    AtomicBoolean analysisRunning = new AtomicBoolean(false);
    AtomicInteger transactions = new AtomicInteger();

    InstructionResource sampleInstruction =
        new InstructionResource(
            "ram:00401000",
            2,
            new ByteSequence(ByteSequence.Encoding.HEX, "31c0", 2),
            "XOR",
            List.of("EAX", "EAX"),
            FlowOverrideValue.NONE,
            "FALL_THROUGH",
            "FALL_THROUGH",
            "ram:00401002");

    AddressService addresses =
        proxy(
            AddressService.class,
            (method, args) -> {
              assertEquals("resolveAddress", method);
              return new AddressResource(
                  "ram:00401000", true, true, null, null, null, null);
            });

    ListingService listing =
        proxy(
            ListingService.class,
            (method, args) -> {
              calledMethod.set(method);
              calledArgs.set(Arrays.asList(args));
              return switch (method) {
                case "assembleInstructions" -> {
                  @SuppressWarnings("unchecked")
                  List<String> lines = (List<String>) args[1];
                  if (lines.contains("BAD_SLEIGH")) {
                    throw new IllegalArgumentException("invalid assembly syntax");
                  }
                  yield List.of(sampleInstruction);
                }
                case "disassembleInstructions" -> List.of(sampleInstruction);
                case "clearCodeUnits" ->
                    new CodeUnitClearReceipt("ram:00401000", "ram:00401004", true);
                default -> throw new AssertionError(method);
              };
            });

    MemoryService memory =
        proxy(
            MemoryService.class,
            (method, args) -> {
              calledMethod.set(method);
              calledArgs.set(Arrays.asList(args));
              assertEquals("patchMemory", method);
              return null;
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

    Object assembled =
        registry.dispatch(
            "instruction.assemble",
            Map.of(
                "selector", Map.of("address", "0x401000"),
                "instructions", List.of("XOR EAX, EAX")));
    assertEquals("assembleInstructions", calledMethod.get());
    assertEquals(List.of("0x401000", List.of("XOR EAX, EAX"), false), calledArgs.get());
    assertEquals(1, ((List<?>) ((Map<?, ?>) assembled).get("items")).size());
    assertEquals(1, transactions.get());
    assertTrue(registry.method("instruction.assemble").effects().requiresTransaction());
    assertFalse(registry.method("instruction.assemble").effects().allowedDuringAnalysis());

    registry.dispatch(
        "instruction.assemble",
        Map.of(
            "selector", Map.of("address", "0x401000"),
            "instructions", List.of("NOP"),
            "pad_nop", true));
    assertEquals(List.of("0x401000", List.of("NOP"), true), calledArgs.get());
    assertEquals(2, transactions.get());

    IllegalArgumentException badSyntax =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                registry.dispatch(
                    "instruction.assemble",
                    Map.of(
                        "selector", Map.of("address", "0x401000"),
                        "instructions", List.of("BAD_SLEIGH"))));
    ApiFailures.Failure normalizedBadSyntax = ApiFailures.normalize(badSyntax);
    assertEquals(400, normalizedBadSyntax.status());
    assertEquals("invalid_request", normalizedBadSyntax.error().code());

    assertThrows(
        ApiException.class,
        () ->
            registry.dispatch(
                "instruction.assemble",
                Map.of("selector", Map.of("address", "0x401000"), "instructions", List.of())));

    registry.dispatch(
        "instruction.disassemble",
        Map.of("selector", Map.of("kind", "address", "address", "0x401000")));
    assertEquals("disassembleInstructions", calledMethod.get());
    assertEquals(
        List.of(new AddressOrRangeScope.AddressScope("0x401000"), true), calledArgs.get());

    registry.dispatch(
        "instruction.disassemble",
        Map.of(
            "selector", Map.of("kind", "range", "start", "0x401000", "end", "0x401010"),
            "follow_flow", false));
    assertEquals(
        List.of(new AddressOrRangeScope.RangeScope("0x401000", "0x401010"), false),
        calledArgs.get());

    assertThrows(
        ApiException.class,
        () ->
            registry.dispatch(
                "instruction.disassemble",
                Map.of(
                    "selector",
                    Map.of("kind", "address", "address", "0x401000", "start", "0x401000"))));

    Object cleared =
        registry.dispatch(
            "code_unit.clear",
            Map.of(
                "selector", Map.of("kind", "range", "start", "0x401000", "end", "0x401004"),
                "clear_context", true));
    assertEquals("clearCodeUnits", calledMethod.get());
    assertEquals(
        List.of(new AddressOrRangeScope.RangeScope("0x401000", "0x401004"), true),
        calledArgs.get());
    assertEquals(
        Map.of("start", "ram:00401000", "end", "ram:00401004", "cleared", true), cleared);
    assertTrue(registry.method("code_unit.clear").effects().destructive());
    assertTrue(registry.method("code_unit.clear").effects().idempotent());

    Map<String, Object> writePatch =
        Map.of("bytes", Map.of("encoding", "hex", "data", "31c0", "length", 2));
    Object written =
        registry.dispatch(
            "memory.write",
            Map.of(
                "selector", Map.of("address", "0x401000"),
                "patch", writePatch,
                "clear_existing", true,
                "disassemble", true));
    assertEquals("patchMemory", calledMethod.get());
    assertEquals(
        List.of(
            "0x401000",
            new ByteSequence(ByteSequence.Encoding.HEX, "31c0", 2),
            true,
            true),
        calledArgs.get());
    assertEquals(Map.of("start", "ram:00401000", "length", 2), written);

    registry.dispatch(
        "memory.write",
        Map.of("selector", Map.of("address", "0x401000"), "patch", writePatch));
    assertEquals(
        List.of(
            "0x401000",
            new ByteSequence(ByteSequence.Encoding.HEX, "31c0", 2),
            false,
            false),
        calledArgs.get());

    analysisRunning.set(true);
    for (Map.Entry<String, Map<String, Object>> entry :
        List.of(
            Map.entry(
                "instruction.assemble",
                Map.<String, Object>of(
                    "selector", Map.of("address", "0x401000"), "instructions", List.of("NOP"))),
            Map.entry(
                "instruction.disassemble",
                Map.<String, Object>of(
                    "selector", Map.of("kind", "address", "address", "0x401000"))),
            Map.entry(
                "code_unit.clear",
                Map.<String, Object>of(
                    "selector", Map.of("kind", "address", "address", "0x401000"))),
            Map.entry(
                "memory.write",
                Map.<String, Object>of(
                    "selector", Map.of("address", "0x401000"),
                    "patch", writePatch)))) {
      ApiException conflict =
          assertThrows(
              ApiException.class, () -> registry.dispatch(entry.getKey(), entry.getValue()));
      assertEquals(409, conflict.error().status());
      assertEquals("analysis_in_progress", conflict.error().code());
    }
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
