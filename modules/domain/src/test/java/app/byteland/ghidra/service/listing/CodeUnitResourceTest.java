package app.byteland.ghidra.service.listing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import java.lang.reflect.RecordComponent;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

class CodeUnitResourceTest {

  @Test
  void recordDeclaresEightComponentsWithoutValueOrRepresentation() {
    List<String> names =
        Arrays.stream(CodeUnitResource.class.getRecordComponents())
            .map(RecordComponent::getName)
            .toList();

    assertEquals(
        List.of("address", "kind", "length", "bytes", "text", "mnemonic", "operands", "dataType"),
        names);
  }

  @Test
  void instructionResourceCopiesOperandsDefensively() {
    List<String> mutableOperands = new ArrayList<>(List.of("EAX", "0x1"));
    ByteSequence bytes = new ByteSequence(ByteSequence.Encoding.HEX, "b801000000", 5);

    CodeUnitResource resource =
        new CodeUnitResource(
            "ram:00401000",
            CodeUnitResource.Kind.INSTRUCTION,
            5,
            bytes,
            "MOV EAX,0x1",
            "MOV",
            mutableOperands,
            null);

    mutableOperands.add("EBX");
    assertEquals("ram:00401000", resource.address());
    assertEquals(CodeUnitResource.Kind.INSTRUCTION, resource.kind());
    assertEquals(5, resource.length());
    assertEquals(bytes, resource.bytes());
    assertEquals("MOV EAX,0x1", resource.text());
    assertEquals("MOV", resource.mnemonic());
    assertEquals(List.of("EAX", "0x1"), resource.operands());
    assertNull(resource.dataType());
    assertThrows(UnsupportedOperationException.class, () -> resource.operands().add("ECX"));
  }

  @Test
  void dataResourceKeepsDataTypeAndNullInstructionFields() {
    DataTypeReference dataType = DataTypeReference.named("/dword");
    ByteSequence bytes = new ByteSequence(ByteSequence.Encoding.HEX, "2a000000", 4);

    CodeUnitResource resource =
        new CodeUnitResource(
            "ram:00402000", CodeUnitResource.Kind.DATA, 4, bytes, "dd 2Ah", null, null, dataType);

    assertEquals("ram:00402000", resource.address());
    assertEquals(CodeUnitResource.Kind.DATA, resource.kind());
    assertEquals(4, resource.length());
    assertEquals(bytes, resource.bytes());
    assertEquals("dd 2Ah", resource.text());
    assertNull(resource.mnemonic());
    assertNull(resource.operands());
    assertEquals(dataType, resource.dataType());
  }
}
