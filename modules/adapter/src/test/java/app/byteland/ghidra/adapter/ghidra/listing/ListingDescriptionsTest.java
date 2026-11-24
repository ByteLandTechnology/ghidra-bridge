package app.byteland.ghidra.adapter.ghidra.listing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.listing.CodeUnitResource;
import app.byteland.ghidra.service.listing.DataUnitResource;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;
import java.lang.reflect.Proxy;
import java.util.List;
import org.junit.jupiter.api.Test;

class ListingDescriptionsTest {

  private static final class StubScript extends GhidraScript {
    private StubScript(Program program) {
      set(program, TaskMonitor.DUMMY);
    }

    @Override
    protected void run() {}
  }

  @Test
  void toCodeUnitItemOnDefinedDataPopulatesDataTypeWithoutReadingValueOrRepresentation() {
    byte[] rawBytes = new byte[] {0x2a, 0x00, 0x00, 0x00};
    Program program = initializedProgram(rawBytes);
    GhidraSession session = new GhidraSession(new StubScript(program));
    Address address = stubAddress("ram", "00402000");
    DataType dwordType = stubDataType("/dword");

    Data data =
        proxy(
            Data.class,
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "getAddress", "getMinAddress", "getMaxAddress" -> address;
                  case "getLength" -> rawBytes.length;
                  case "getProgram" -> program;
                  case "getDataType" -> dwordType;
                  case "isDefined" -> true;
                  case "toString" -> "dd 2Ah";
                  case "getValue", "getDefaultValueRepresentation" ->
                      throw new AssertionError("unexpected Data call: " + method.getName());
                  default -> throw new AssertionError(method.getName());
                });

    CodeUnitResource.Kind kind = ListingDescriptions.classify(data);
    CodeUnitResource resource = ListingDescriptions.toCodeUnitItem(data, kind, session);

    assertEquals(CodeUnitResource.Kind.DATA, kind);
    assertEquals(
        new CodeUnitResource(
            "ram:00402000",
            CodeUnitResource.Kind.DATA,
            4,
            new ByteSequence(ByteSequence.Encoding.HEX, "2a000000", 4),
            "dd 2Ah",
            null,
            null,
            DataTypeReference.named("/dword")),
        resource);
  }

  @Test
  void toCodeUnitItemOnUndefinedDataStillPopulatesDataTypeWithoutReadingValueOrRepresentation() {
    byte[] rawBytes = new byte[] {0x00};
    Program program = initializedProgram(rawBytes);
    GhidraSession session = new GhidraSession(new StubScript(program));
    Address address = stubAddress("ram", "00402004");
    DataType undefinedType = stubDataType("/undefined");

    Data undefinedData =
        proxy(
            Data.class,
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "getAddress", "getMinAddress", "getMaxAddress" -> address;
                  case "getLength" -> rawBytes.length;
                  case "getProgram" -> program;
                  case "getDataType" -> undefinedType;
                  case "isDefined" -> false;
                  case "toString" -> "?? 00h";
                  case "getValue", "getDefaultValueRepresentation" ->
                      throw new AssertionError("unexpected Data call: " + method.getName());
                  default -> throw new AssertionError(method.getName());
                });

    CodeUnitResource.Kind kind = ListingDescriptions.classify(undefinedData);
    CodeUnitResource resource = ListingDescriptions.toCodeUnitItem(undefinedData, kind, session);

    assertEquals(CodeUnitResource.Kind.UNDEFINED, kind);
    assertEquals(DataTypeReference.named("/undefined"), resource.dataType());
    assertNull(resource.mnemonic());
    assertNull(resource.operands());
  }

  @Test
  void toCodeUnitItemOnInstructionPopulatesMnemonicAndOperands() {
    byte[] rawBytes = new byte[] {(byte) 0xb8, 0x01, 0x00, 0x00, 0x00};
    Program program = initializedProgram(rawBytes);
    GhidraSession session = new GhidraSession(new StubScript(program));
    Address address = stubAddress("ram", "00401000");

    Instruction instruction =
        proxy(
            Instruction.class,
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "getAddress", "getMinAddress", "getMaxAddress" -> address;
                  case "getLength" -> rawBytes.length;
                  case "getProgram" -> program;
                  case "getMnemonicString" -> "MOV";
                  case "getNumOperands" -> 2;
                  case "getDefaultOperandRepresentation" ->
                      ((Integer) args[0]) == 0 ? "EAX" : "0x1";
                  case "toString" -> "MOV EAX,0x1";
                  default -> throw new AssertionError(method.getName());
                });

    CodeUnitResource.Kind kind = ListingDescriptions.classify(instruction);
    CodeUnitResource resource = ListingDescriptions.toCodeUnitItem(instruction, kind, session);

    assertEquals(CodeUnitResource.Kind.INSTRUCTION, kind);
    assertEquals(
        new CodeUnitResource(
            "ram:00401000",
            CodeUnitResource.Kind.INSTRUCTION,
            5,
            new ByteSequence(ByteSequence.Encoding.HEX, "b801000000", 5),
            "MOV EAX,0x1",
            "MOV",
            List.of("EAX", "0x1"),
            null),
        resource);
  }

  @Test
  void toDataItemStillPopulatesValueAndRepresentationForDataUnitResource() {
    byte[] rawBytes = new byte[] {0x2a, 0x00, 0x00, 0x00};
    Program program = initializedProgram(rawBytes);
    GhidraSession session = new GhidraSession(new StubScript(program));
    Address address = stubAddress("ram", "00402000");
    DataType dwordType = stubDataType("/dword");

    Data data =
        proxy(
            Data.class,
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "getAddress", "getMinAddress", "getMaxAddress" -> address;
                  case "getLength" -> rawBytes.length;
                  case "getProgram" -> program;
                  case "getDataType" -> dwordType;
                  case "getValue" -> 42L;
                  case "getDefaultValueRepresentation" -> "2Ah";
                  default -> throw new AssertionError(method.getName());
                });

    DataUnitResource resource = ListingDescriptions.toDataItem(data, session);

    assertEquals(
        new DataUnitResource(
            "ram:00402000",
            4,
            DataTypeReference.named("/dword"),
            "42",
            "2Ah",
            new ByteSequence(ByteSequence.Encoding.HEX, "2a000000", 4)),
        resource);
  }

  private static Program initializedProgram(byte[] rawBytes) {
    MemoryBlock block =
        proxy(
            MemoryBlock.class,
            (proxy, method, args) -> {
              if ("isInitialized".equals(method.getName())) {
                return true;
              }
              throw new AssertionError(method.getName());
            });
    Memory memory =
        proxy(
            Memory.class,
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "getBlock" -> block;
                  case "getBytes" -> {
                    byte[] destination = (byte[]) args[1];
                    System.arraycopy(rawBytes, 0, destination, 0, destination.length);
                    yield destination.length;
                  }
                  default -> throw new AssertionError(method.getName());
                });
    return proxy(
        Program.class,
        (proxy, method, args) -> {
          if ("getMemory".equals(method.getName())) {
            return memory;
          }
          throw new AssertionError(method.getName());
        });
  }

  private static Address stubAddress(String spaceName, String offsetHex) {
    AddressSpace space =
        proxy(
            AddressSpace.class,
            (proxy, method, args) -> {
              if ("getName".equals(method.getName())) {
                return spaceName;
              }
              throw new AssertionError(method.getName());
            });
    return proxy(
        Address.class,
        (proxy, method, args) ->
            switch (method.getName()) {
              case "getAddressSpace" -> space;
              case "toString" -> offsetHex;
              default -> throw new AssertionError(method.getName());
            });
  }

  private static DataType stubDataType(String pathName) {
    return proxy(
        DataType.class,
        (proxy, method, args) ->
            switch (method.getName()) {
              case "getPathName" -> pathName;
              case "getName" -> pathName.substring(pathName.lastIndexOf('/') + 1);
              case "equals" -> proxy == args[0];
              case "hashCode" -> System.identityHashCode(proxy);
              case "toString" -> pathName;
              default -> throw new AssertionError(method.getName());
            });
  }

  private interface Invocation {
    Object apply(Object proxy, java.lang.reflect.Method method, Object[] args);
  }

  private static <T> T proxy(Class<T> type, Invocation invocation) {
    return type.cast(
        Proxy.newProxyInstance(
            type.getClassLoader(), new Class<?>[] {type}, invocation::apply));
  }
}
