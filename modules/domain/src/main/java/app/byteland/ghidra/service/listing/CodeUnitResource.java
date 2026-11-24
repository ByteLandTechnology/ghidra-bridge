package app.byteland.ghidra.service.listing;

import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import java.util.List;

/**
 * Describes an instruction, defined data item, or undefined byte in the program disassembly.
 *
 * @param address canonical start address
 * @param kind code unit classification
 * @param length code unit byte length
 * @param bytes raw code unit bytes
 * @param text full rendered code unit text
 * @param mnemonic instruction mnemonic, or {@code null} for data
 * @param operands rendered instruction operands, or {@code null} for data
 * @param dataType defined data type reference, or {@code null} for instructions
 */
public record CodeUnitResource(
    String address,
    Kind kind,
    int length,
    ByteSequence bytes,
    String text,
    String mnemonic,
    List<String> operands,
    DataTypeReference dataType) {
  /** Copies optional operand strings into an immutable list. */
  public CodeUnitResource {
    operands = immutableCopyOrNull(operands);
  }

  /**
   * Returns the rendered instruction operands, or {@code null} for non-instruction units.
   *
   * @return immutable operand list, or {@code null}
   */
  @Override
  public List<String> operands() {
    return immutableCopyOrNull(operands);
  }

  private static <T> List<T> immutableCopyOrNull(List<T> values) {
    return values == null ? null : List.copyOf(values);
  }

  /**
   * Classification of a program code unit.
   */
  public enum Kind {
    /** Disassembled machine instruction. */
    INSTRUCTION,
    /** Defined data item with an assigned data type. */
    DATA,
    /** Undefined data byte without an assigned data type. */
    UNDEFINED
  }
}
