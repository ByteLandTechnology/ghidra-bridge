package app.byteland.ghidra.service.listing;

import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import java.util.List;

/**
 * Listing code unit summary for an instruction, defined data, or undefined byte unit.
 *
 * @param address canonical code unit start address
 * @param kind code unit classification
 * @param length byte length of the code unit
 * @param bytes raw byte sequence when available
 * @param text formatted assembly or data representation
 * @param mnemonic instruction or data mnemonic
 * @param operands formatted operand strings when applicable
 * @param dataType defined data type reference for data code units
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
  /** Copies non-null operand lists into an immutable collection. */
  public CodeUnitResource {
    operands = immutableCopyOrNull(operands);
  }

  /**
   * Returns an immutable copy of the formatted operand list.
   *
   * @return operand strings or {@code null}
   */
  @Override
  public List<String> operands() {
    return immutableCopyOrNull(operands);
  }

  private static <T> List<T> immutableCopyOrNull(List<T> values) {
    return values == null ? null : List.copyOf(values);
  }

  /** Classification of program listing code units. */
  public enum Kind {
    /** Disassembled machine instruction. */
    INSTRUCTION,
    /** Defined data item. */
    DATA,
    /** Undefined data unit. */
    UNDEFINED
  }
}
