package app.byteland.ghidra.adapter.ghidra.listing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.scan.AddressScanRanges;
import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.ScanProgress;
import app.byteland.ghidra.service.listing.CodeUnitResource;
import app.byteland.ghidra.service.listing.DataUnitResource;
import app.byteland.ghidra.service.listing.FlowOverrideValue;
import app.byteland.ghidra.service.listing.InstructionResource;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.DefaultAddressFactory;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.lang.InstructionPrototype;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.RefType;
import ghidra.util.task.TaskMonitor;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.Arrays;
import java.util.List;
import java.util.NavigableMap;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;

class ListingScanQueriesTest {
  private static final GenericAddressSpace RAM =
      new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 0);
  private static final AddressFactory FACTORY = new DefaultAddressFactory(new AddressSpace[] {RAM});

  private static final class StubScript extends GhidraScript {
    private StubScript(Program program) {
      set(program, TaskMonitor.DUMMY);
    }

    @Override
    protected void run() {}
  }

  @Test
  void listCodeUnitsScansForwardWithCursorKindFilterAndEndBound() {
    NavigableMap<Address, Instruction> instructions = new TreeMap<>();
    NavigableMap<Address, Data> definedData = new TreeMap<>();
    NavigableMap<Address, Data> undefinedData = new TreeMap<>();
    Program program = buildProgram(instructions, definedData, undefinedData);

    instructions.put(addr(0x1002), stubInstruction(program, 0x1002, 2, "NOP"));
    definedData.put(addr(0x1004), stubData(program, 0x1004, 4, true, "/int", 7));
    undefinedData.put(addr(0x1008), stubData(program, 0x1008, 1, false, "/undefined1", 0));
    instructions.put(addr(0x1010), stubInstruction(program, 0x1010, 2, "RET"));

    ListingServiceImpl service = new ListingServiceImpl(new GhidraSession(new StubScript(program)));

    Page<CodeUnitResource> firstPage =
        service.listCodeUnits(
            new AddressScanOptions("0x1000", "0x100a", 1_000), 2, "all", null);
    assertEquals(
        List.of("ram:00001002", "ram:00001004"),
        firstPage.items().stream().map(CodeUnitResource::address).toList());
    assertEquals("ram:00001004", firstPage.nextCursor());
    assertEquals(ScanProgress.StopReason.LIMIT, firstPage.scanProgress().stopReason());

    Page<CodeUnitResource> secondPage =
        service.listCodeUnits(
            new AddressScanOptions("0x1000", "0x100a", 1_000), 2, "all", firstPage.nextCursor());
    assertEquals(
        List.of("ram:00001008"),
        secondPage.items().stream().map(CodeUnitResource::address).toList());
    assertNull(secondPage.nextCursor());
    assertTrue(secondPage.scanProgress().complete());

    Page<CodeUnitResource> filteredPage =
        service.listCodeUnits(
            new AddressScanOptions("0x1002", "0x1010", 1_000), 10, "instruction", null);
    assertEquals(
        List.of("ram:00001002", "ram:00001010"),
        filteredPage.items().stream().map(CodeUnitResource::address).toList());
  }

  @Test
  void listInstructionsAndDataUnitsScanForwardAndRespectEndBound() {
    NavigableMap<Address, Instruction> instructions = new TreeMap<>();
    NavigableMap<Address, Data> definedData = new TreeMap<>();
    NavigableMap<Address, Data> undefinedData = new TreeMap<>();
    Program program = buildProgram(instructions, definedData, undefinedData);

    instructions.put(addr(0x2000), stubInstruction(program, 0x2000, 2, "PUSH"));
    instructions.put(addr(0x2004), stubInstruction(program, 0x2004, 2, "MOV"));
    instructions.put(addr(0x2008), stubInstruction(program, 0x2008, 1, "RET"));

    definedData.put(addr(0x3002), stubData(program, 0x3002, 2, true, "/short", 1));
    definedData.put(addr(0x3006), stubData(program, 0x3006, 4, true, "/int", 2));
    definedData.put(addr(0x3010), stubData(program, 0x3010, 4, true, "/int", 3));

    ListingServiceImpl service = new ListingServiceImpl(new GhidraSession(new StubScript(program)));

    Page<InstructionResource> instrPage1 =
        service.listInstructions(new AddressScanOptions("0x2000", "0x2006", 1_000), 1, null);
    assertEquals(List.of("ram:00002000"), instrPage1.items().stream().map(InstructionResource::address).toList());
    assertEquals(FlowOverrideValue.NONE, instrPage1.items().getFirst().flowOverride());
    assertEquals("ram:00002000", instrPage1.nextCursor());

    Page<InstructionResource> instrPage2 =
        service.listInstructions(
            new AddressScanOptions("0x2000", "0x2006", 1_000), 5, instrPage1.nextCursor());
    assertEquals(List.of("ram:00002004"), instrPage2.items().stream().map(InstructionResource::address).toList());
    assertNull(instrPage2.nextCursor());

    Page<DataUnitResource> dataPage1 =
        service.listDataUnits(new AddressScanOptions("0x3000", "0x3008", 1_000), 1, null);
    assertEquals(List.of("ram:00003002"), dataPage1.items().stream().map(DataUnitResource::address).toList());
    assertEquals("ram:00003002", dataPage1.nextCursor());

    Page<DataUnitResource> dataPage2 =
        service.listDataUnits(
            new AddressScanOptions("0x3000", "0x3008", 1_000), 5, dataPage1.nextCursor());
    assertEquals(List.of("ram:00003006"), dataPage2.items().stream().map(DataUnitResource::address).toList());
    assertNull(dataPage2.nextCursor());
  }

  @Test
  void addressScanRangesResolvedExposesOnlyForwardBoundaryHelpers() {
    AddressScanRanges.Resolved bounded = AddressScanRanges.of(addr(0x1000), addr(0x1010));
    assertFalse(bounded.afterEnd(addr(0x1000)));
    assertFalse(bounded.afterEnd(addr(0x1010)));
    assertTrue(bounded.afterEnd(addr(0x1011)));
    assertFalse(AddressScanRanges.of(addr(0x1000), null).afterEnd(addr(0x9999)));
    assertEquals(
        java.util.Set.of(
            "start", "end", "startText", "endText", "afterEnd", "toString", "hashCode", "equals"),
        Arrays.stream(AddressScanRanges.Resolved.class.getDeclaredMethods())
            .map(Method::getName)
            .collect(java.util.stream.Collectors.toSet()));
  }

  private static Address addr(long offset) {
    return RAM.getAddress(offset);
  }

  private static Program buildProgram(
      NavigableMap<Address, Instruction> instructions,
      NavigableMap<Address, Data> definedData,
      NavigableMap<Address, Data> undefinedData) {
    Memory memory =
        proxy(
            Memory.class,
            (method, args) -> {
              if ("getBlock".equals(method)) return null;
              throw new AssertionError(method);
            });
    Listing listing =
        proxy(
            Listing.class,
            (method, args) ->
                switch (method) {
                  case "getInstructionAt" -> instructions.get((Address) args[0]);
                  case "getInstructionAfter" -> higherValue(instructions, (Address) args[0]);
                  case "getDefinedDataAt" -> definedData.get((Address) args[0]);
                  case "getDefinedDataAfter" -> higherValue(definedData, (Address) args[0]);
                  case "getUndefinedDataAt" -> undefinedData.get((Address) args[0]);
                  case "getUndefinedDataAfter" -> higherValue(undefinedData, (Address) args[0]);
                  default -> throw new AssertionError(method);
                });
    return proxy(
        Program.class,
        (method, args) ->
            switch (method) {
              case "getAddressFactory" -> FACTORY;
              case "getListing" -> listing;
              case "getMemory" -> memory;
              case "getMinAddress" -> addr(0x1000);
              case "getMaxAddress" -> addr(0xffff);
              default -> throw new AssertionError(method);
            });
  }

  private static <V extends CodeUnit> V higherValue(NavigableMap<Address, V> map, Address address) {
    var entry = map.higherEntry(address);
    return entry == null ? null : entry.getValue();
  }

  private static Instruction stubInstruction(
      Program program, long offset, int length, String mnemonic) {
    Address start = addr(offset);
    Address end = addr(offset + length - 1);
    Address fallThrough = addr(offset + length);
    InstructionPrototype prototype =
        proxy(
            InstructionPrototype.class,
            (method, args) -> {
              if ("getFlowType".equals(method)) return RefType.FALL_THROUGH;
              throw new AssertionError(method);
            });
    return proxy(
        Instruction.class,
        (method, args) ->
            switch (method) {
              case "getAddress", "getMinAddress" -> start;
              case "getMaxAddress" -> end;
              case "getLength" -> length;
              case "getProgram" -> program;
              case "getMnemonicString", "toString" -> mnemonic;
              case "getNumOperands" -> 0;
              case "getFlowOverride" -> FlowOverride.NONE;
              case "getPrototype" -> prototype;
              case "getInstructionContext" -> null;
              case "getFlowType" -> RefType.FALL_THROUGH;
              case "getFallThrough" -> fallThrough;
              default -> throw new AssertionError(method);
            });
  }

  private static Data stubData(
      Program program, long offset, int length, boolean defined, String pathName, Object value) {
    Address start = addr(offset);
    Address end = addr(offset + length - 1);
    DataType dataType =
        proxy(
            DataType.class,
            (method, args) ->
                switch (method) {
                  case "getPathName" -> pathName;
                  case "getName" -> pathName.substring(1);
                  case "hashCode" -> System.identityHashCode(args);
                  case "equals" -> false;
                  default -> throw new AssertionError(method);
                });
    return proxy(
        Data.class,
        (method, args) ->
            switch (method) {
              case "getAddress", "getMinAddress" -> start;
              case "getMaxAddress" -> end;
              case "getLength" -> length;
              case "getProgram" -> program;
              case "isDefined" -> defined;
              case "getDataType" -> dataType;
              case "getValue" -> value;
              case "getDefaultValueRepresentation", "toString" -> String.valueOf(value);
              default -> throw new AssertionError(method);
            });
  }

  private interface Handler {
    Object invoke(String method, Object[] args);
  }

  private static <T> T proxy(Class<T> type, Handler handler) {
    return type.cast(
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (proxy, method, args) -> {
              if (method.getDeclaringClass() == Object.class) {
                return switch (method.getName()) {
                  case "toString" -> String.valueOf(handler.invoke("toString", args));
                  case "hashCode" -> System.identityHashCode(proxy);
                  case "equals" -> proxy == args[0];
                  default -> null;
                };
              }
              return handler.invoke(method.getName(), args);
            }));
  }
}
