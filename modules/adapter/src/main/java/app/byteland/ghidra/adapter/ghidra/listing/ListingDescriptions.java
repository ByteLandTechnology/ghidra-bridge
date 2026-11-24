package app.byteland.ghidra.adapter.ghidra.listing;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.FieldProjections;
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
import java.util.Set;

final class ListingDescriptions {
  private ListingDescriptions() {}

  static CodeUnitResource toCodeUnitItem(
      CodeUnit codeUnit, CodeUnitResource.Kind kind, GhidraSession context) {
    return toCodeUnitItem(codeUnit, kind, context, null);
  }

  static CodeUnitResource toCodeUnitItem(
      CodeUnit codeUnit,
      CodeUnitResource.Kind kind,
      GhidraSession context,
      Set<String> fields) {
    Instruction instruction = codeUnit instanceof Instruction value ? value : null;
    Data data = codeUnit instanceof Data value ? value : null;
    return new CodeUnitResource(
        FieldProjections.allows(fields, "address")
            ? AddressUtil.canonicalAddress(codeUnit.getAddress())
            : null,
        FieldProjections.allows(fields, "kind") ? kind : null,
        FieldProjections.allows(fields, "length") ? codeUnit.getLength() : 0,
        FieldProjections.allows(fields, "bytes") ? bytes(codeUnit, context) : null,
        FieldProjections.allows(fields, "text") ? codeUnit.toString() : null,
        instruction != null && FieldProjections.allows(fields, "mnemonic")
            ? instruction.getMnemonicString()
            : null,
        instruction != null && FieldProjections.allows(fields, "operands")
            ? operandsOf(instruction)
            : null,
        data != null && FieldProjections.allows(fields, "data_type")
            ? GhidraDataTypeReferences.toReference(data.getDataType())
            : null);
  }

  static InstructionResource toInstructionItem(Instruction instruction, GhidraSession context) {
    return toInstructionItem(instruction, context, null);
  }

  static InstructionResource toInstructionItem(
      Instruction instruction, GhidraSession context, Set<String> fields) {
    return new InstructionResource(
        FieldProjections.allows(fields, "address")
            ? AddressUtil.canonicalAddress(instruction.getAddress())
            : null,
        FieldProjections.allows(fields, "length") ? instruction.getLength() : 0,
        context != null && FieldProjections.allows(fields, "bytes")
            ? bytes(instruction, context)
            : null,
        FieldProjections.allows(fields, "mnemonic") ? instruction.getMnemonicString() : null,
        FieldProjections.allows(fields, "operands") ? operandsOf(instruction) : null,
        FieldProjections.allows(fields, "flow_override")
            ? FlowOverrideValue.valueOf(instruction.getFlowOverride().name())
            : null,
        FieldProjections.allows(fields, "default_flow_type")
            ? instruction.getPrototype().getFlowType(instruction.getInstructionContext()).getName()
            : null,
        FieldProjections.allows(fields, "flow_type")
            ? instruction.getFlowType().getName()
            : null,
        FieldProjections.allows(fields, "fall_through")
            ? AddressUtil.canonicalAddress(instruction.getFallThrough())
            : null);
  }

  static DataUnitResource toDataItem(Data data, GhidraSession context) {
    return toDataItem(data, context, null);
  }

  static DataUnitResource toDataItem(Data data, GhidraSession context, Set<String> fields) {
    return new DataUnitResource(
        FieldProjections.allows(fields, "address")
            ? AddressUtil.canonicalAddress(data.getAddress())
            : null,
        FieldProjections.allows(fields, "length") ? data.getLength() : 0,
        FieldProjections.allows(fields, "data_type")
            ? GhidraDataTypeReferences.toReference(data.getDataType())
            : null,
        FieldProjections.allows(fields, "value") ? String.valueOf(data.getValue()) : null,
        FieldProjections.allows(fields, "representation") ? formatScalar(data) : null,
        FieldProjections.allows(fields, "bytes") ? bytes(data, context) : null);
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
   * Returns the bytes of a code unit. Returns null for a code unit in uninitialized memory,
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
