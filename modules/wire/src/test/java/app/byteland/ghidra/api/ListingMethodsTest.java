package app.byteland.ghidra.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.ScanProgress;
import app.byteland.ghidra.service.TransactionRunner;
import app.byteland.ghidra.service.address.AddressService;
import app.byteland.ghidra.service.analysis.AnalysisService;
import app.byteland.ghidra.service.comment.CommentService;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.datatype.DataTypeService;
import app.byteland.ghidra.service.decompilation.DecompilationService;
import app.byteland.ghidra.service.function.FunctionService;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService;
import app.byteland.ghidra.service.listing.CodeUnitResource;
import app.byteland.ghidra.service.listing.DataUnitResource;
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
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class ListingMethodsTest {
  @Test
  void listingScanMethodsForwardParametersWithoutDirection() throws Exception {
    AtomicReference<String> calledMethod = new AtomicReference<>();
    AtomicReference<List<Object>> calledArgs = new AtomicReference<>();
    ScanProgress progress =
        new ScanProgress(
            ScanProgress.Kind.ADDRESS,
            "ram:00100000",
            "ram:00100010",
            "ram:00100000",
            "ram:00100004",
            false,
            ScanProgress.StopReason.LIMIT,
            1L);

    ListingService listing =
        proxy(
            ListingService.class,
            (method, args) -> {
              calledMethod.set(method);
              calledArgs.set(Arrays.asList(args));
              return switch (method) {
                case "listCodeUnits" ->
                    Page.scanned(
                        List.of(
                            new CodeUnitResource(
                                "ram:00100000",
                                CodeUnitResource.Kind.INSTRUCTION,
                                1,
                                new ByteSequence(ByteSequence.Encoding.HEX, "90", 1),
                                "NOP",
                                "NOP",
                                List.of(),
                                null,
                                null,
                                null)),
                        25,
                        "ram:00100000",
                        progress);
                case "listInstructions" ->
                    Page.scanned(
                        List.of(
                            new InstructionResource(
                                "ram:00100000",
                                1,
                                new ByteSequence(ByteSequence.Encoding.HEX, "90", 1),
                                "NOP",
                                List.of(),
                                FlowOverrideValue.NONE,
                                "FALL_THROUGH",
                                "FALL_THROUGH",
                                "ram:00100001")),
                        15,
                        "ram:00100000",
                        progress);
                case "listDataUnits" ->
                    Page.scanned(
                        List.of(
                            new DataUnitResource(
                                "ram:00100004",
                                4,
                                DataTypeReference.named("/int"),
                                "42",
                                "2ah",
                                new ByteSequence(ByteSequence.Encoding.HEX, "2a000000", 4))),
                        10,
                        "ram:00100004",
                        progress);
                default -> throw new AssertionError(method);
              };
            });

    BridgeServices services =
        new BridgeServices(
            unused(ProgramService.class),
            unused(AddressService.class),
            unused(CommentService.class),
            unused(ReferenceService.class),
            unused(MemoryService.class),
            listing,
            unused(FunctionService.class),
            unused(GlobalVariableService.class),
            unused(AnalysisService.class),
            unused(DecompilationService.class),
            unused(SymbolService.class),
            unused(DataTypeService.class),
            unused(TransactionRunner.class),
            "test");
    ApiRegistry registry = new ApiRegistry(services, "test", Map::of, () -> {});

    Map<?, ?> codeUnitPage =
        (Map<?, ?>)
            registry.dispatch(
                "code_unit.list",
                Map.of(
                    "filter", Map.of("kind", "instruction"),
                    "page", Map.of("limit", 25),
                    "scan",
                        Map.of(
                            "range", Map.of("start", "0x100000", "end", "0x100010"),
                            "timeout_ms", 500)));
    assertEquals("listCodeUnits", calledMethod.get());
    assertEquals(
        Arrays.asList(
            new AddressScanOptions("0x100000", "0x100010", 500), 25, "instruction", null),
        calledArgs.get());
    registry.dispatch(
        "code_unit.list",
        Map.of(
            "filter", Map.of("kind", "instruction"),
            "page", Map.of("limit", 25, "cursor", codeUnitPage.get("next_cursor")),
            "scan",
                Map.of(
                    "range", Map.of("start", "0x100000", "end", "0x100010"),
                    "timeout_ms", 500)));
    assertEquals(
        List.of(
            new AddressScanOptions("0x100000", "0x100010", 500),
            25,
            "instruction",
            "ram:00100000"),
        calledArgs.get());
    assertFalse(registry.method("code_unit.list").effects().requiresTransaction());

    Map<?, ?> instructionPage =
        (Map<?, ?>)
            registry.dispatch(
                "instruction.list",
                Map.of(
                    "page", Map.of("limit", 15),
                    "scan",
                        Map.of(
                            "range", Map.of("start", "0x100000", "end", "0x100010"),
                            "timeout_ms", 600)));
    assertEquals("listInstructions", calledMethod.get());
    assertEquals(
        Arrays.asList(new AddressScanOptions("0x100000", "0x100010", 600), 15, null),
        calledArgs.get());
    registry.dispatch(
        "instruction.list",
        Map.of(
            "page", Map.of("limit", 15, "cursor", instructionPage.get("next_cursor")),
            "scan",
                Map.of(
                    "range", Map.of("start", "0x100000", "end", "0x100010"),
                    "timeout_ms", 600)));
    assertEquals(
        List.of(new AddressScanOptions("0x100000", "0x100010", 600), 15, "ram:00100000"),
        calledArgs.get());

    Map<?, ?> dataUnitPage =
        (Map<?, ?>)
            registry.dispatch(
                "data_unit.list",
                Map.of(
                    "page", Map.of("limit", 10),
                    "scan",
                        Map.of(
                            "range", Map.of("start", "0x100000", "end", "0x100010"),
                            "timeout_ms", 700)));
    assertEquals("listDataUnits", calledMethod.get());
    assertEquals(
        Arrays.asList(new AddressScanOptions("0x100000", "0x100010", 700), 10, null),
        calledArgs.get());
    registry.dispatch(
        "data_unit.list",
        Map.of(
            "page", Map.of("limit", 10, "cursor", dataUnitPage.get("next_cursor")),
            "scan",
                Map.of(
                    "range", Map.of("start", "0x100000", "end", "0x100010"),
                    "timeout_ms", 700)));
    assertEquals(
        List.of(new AddressScanOptions("0x100000", "0x100010", 700), 10, "ram:00100004"),
        calledArgs.get());

    assertThrows(
        ApiException.class,
        () ->
            registry.dispatch(
                "code_unit.list", Map.of("filter", Map.of("direction", "reverse"))));
    assertThrows(
        ApiException.class,
        () -> registry.dispatch("instruction.list", Map.of("scan", Map.of("direction", "reverse"))));
    assertThrows(
        ApiException.class,
        () -> registry.dispatch("data_unit.list", Map.of("scan", Map.of("direction", "reverse"))));
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
