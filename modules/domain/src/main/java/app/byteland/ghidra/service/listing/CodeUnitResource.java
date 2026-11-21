package app.byteland.ghidra.service.listing;

import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import java.util.List;

/**
 * Represents an instruction, defined data item, or undefined byte unit in the listing.
 *
 * @param address canonical start address
 * @param kind code unit classification
 * @param length unit length in bytes
 * @param bytes raw byte sequence
 * @param text formatted listing representation
 * @param mnemonic instruction or data mnemonic
 * @param operands rendered operand strings for instructions
 * @param dataType data type reference for data units
 * @param value formatted scalar or string value for data units
 * @param representation human-readable value representation for data units
 */
public record CodeUnitResource(
    String address,
    Kind kind,
    int length,
    ByteSequence bytes,
    String text,
    String mnemonic,
    List<String> operands,
    DataTypeReference dataType,
    String value,
    String representation) {
  /** Copies operand strings into an immutable list when present. */
  public CodeUnitResource {
    operands = immutableCopyOrNull(operands);
  }

  /**
   * Returns an immutable copy of instruction operand strings, or null when absent.
   *
   * @return immutable operand list or null
   */
  @Override
  public List<String> operands() {
    return immutableCopyOrNull(operands);
  }

  private static <T> List<T> immutableCopyOrNull(List<T> values) {
    return values == null ? null : List.copyOf(values);
  }

  /** Listing code unit categories. */
  public enum Kind {
    /** Disassembled machine instruction. */
    INSTRUCTION,
    /** Defined data item. */
    DATA,
    /** Undefined listing byte unit. */
    UNDEFINED
  }
}
