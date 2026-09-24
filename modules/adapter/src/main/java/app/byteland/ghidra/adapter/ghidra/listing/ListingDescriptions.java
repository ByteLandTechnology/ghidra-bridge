package app.byteland.ghidra.adapter.ghidra.listing;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraDataTypeReferences;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.listing.CodeUnitResource;
import app.byteland.ghidra.service.listing.DataUnitResource;
import app.byteland.ghidra.service.listing.FlowOverrideValue;
import app.byteland.ghidra.service.listing.InstructionResource;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import java.util.ArrayList;
import java.util.List;

final class ListingDescriptions {
  private ListingDescriptions() {}

  static CodeUnitResource toCodeUnitItem(
      CodeUnit codeUnit, CodeUnitResource.Kind kind, GhidraSession context) {
    Instruction instruction = codeUnit instanceof Instruction value ? value : null;
    Data data = codeUnit instanceof Data value ? value : null;
    return new CodeUnitResource(
        AddressUtil.canonicalAddress(codeUnit.getAddress()),
        kind,
        codeUnit.getLength(),
        bytes(codeUnit, context),
        codeUnit.toString(),
        instruction == null ? null : instruction.getMnemonicString(),
        instruction == null ? null : operandsOf(instruction),
        data == null ? null : GhidraDataTypeReferences.toReference(data.getDataType()),
        data == null ? null : String.valueOf(data.getValue()),
        data == null ? null : formatScalar(data));
  }

  static InstructionResource toInstructionItem(Instruction instruction, GhidraSession context) {
    return new InstructionResource(
        AddressUtil.canonicalAddress(instruction.getAddress()),
        instruction.getLength(),
        context == null ? null : bytes(instruction, context),
        instruction.getMnemonicString(),
        operandsOf(instruction),
        FlowOverrideValue.valueOf(instruction.getFlowOverride().name()),
        instruction.getPrototype().getFlowType(instruction.getInstructionContext()).getName(),
        instruction.getFlowType().getName(),
        AddressUtil.canonicalAddress(instruction.getFallThrough()));
  }

  static DataUnitResource toDataItem(Data data, GhidraSession context) {
    return new DataUnitResource(
        AddressUtil.canonicalAddress(data.getAddress()),
        data.getLength(),
        GhidraDataTypeReferences.toReference(data.getDataType()),
        String.valueOf(data.getValue()),
        formatScalar(data),
        bytes(data, context));
  }

  static CodeUnitResource.Kind classify(CodeUnit codeUnit) {
    if (codeUnit instanceof Instruction) return CodeUnitResource.Kind.INSTRUCTION;
    if (codeUnit instanceof Data data) {
      return data.isDefined() ? CodeUnitResource.Kind.DATA : CodeUnitResource.Kind.UNDEFINED;
    }
    return CodeUnitResource.Kind.UNDEFINED;
  }

  static String formatScalar(Data data) {
    String representation = data.getDefaultValueRepresentation();
    if (representation != null) return representation;
    return String.valueOf(data.getValue());
  }

  private static List<String> operandsOf(Instruction instruction) {
    List<String> operands = new ArrayList<>();
    for (int index = 0; index < instruction.getNumOperands(); index++) {
      operands.add(String.valueOf(instruction.getDefaultOperandRepresentation(index)));
    }
    return List.copyOf(operands);
  }

  /**
   * Returns the bytes of a code unit, or null when the code unit is in uninitialized memory
   * such as {@code .bss}. That memory has no bytes, so the response omits the field.
   */
  private static ByteSequence bytes(CodeUnit codeUnit, GhidraSession context) {
    if (!isInitialized(codeUnit)) {
      return null;
    }
    try {
      byte[] values = context.script().getBytes(codeUnit.getAddress(), codeUnit.getLength());
      return new ByteSequence(
          ByteSequence.Encoding.HEX, java.util.HexFormat.of().formatHex(values), values.length);
    } catch (MemoryAccessException exception) {
      throw new IllegalArgumentException(
          "unable to read code unit bytes: " + exception.getMessage(), exception);
    }
  }

  private static boolean isInitialized(CodeUnit codeUnit) {
    Memory memory = codeUnit.getProgram().getMemory();
    MemoryBlock first = memory.getBlock(codeUnit.getMinAddress());
    MemoryBlock last = memory.getBlock(codeUnit.getMaxAddress());
    return first != null && first.isInitialized() && last != null && last.isInitialized();
  }
}
