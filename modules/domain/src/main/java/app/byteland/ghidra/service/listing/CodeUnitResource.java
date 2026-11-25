package app.byteland.ghidra.service.listing;

import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import java.util.List;

/**
 * Instruction, defined data, or undefined code unit in the program listing.
 *
 * @param address code unit start address
 * @param kind code unit classification
 * @param length byte length of the code unit
 * @param bytes raw code unit bytes
 * @param text formatted listing representation
 * @param mnemonic instruction or data mnemonic, or {@code null}
 * @param operands formatted operand representations, or {@code null}
 * @param dataType defined data type reference for data units, or {@code null}
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
  /** Defensively copies non-null {@code operands}. */
  public CodeUnitResource {
    operands = immutableCopyOrNull(operands);
  }

  /**
   * Returns formatted operand representations, or {@code null}.
   *
   * @return operand list, or {@code null}
   */
  @Override
  public List<String> operands() {
    return immutableCopyOrNull(operands);
  }

  private static <T> List<T> immutableCopyOrNull(List<T> values) {
    return values == null ? null : List.copyOf(values);
  }

  /** Classification of a listing code unit. */
  public enum Kind {
    /** Disassembled machine instruction. */
    INSTRUCTION,
    /** Defined data item. */
    DATA,
    /** Undefined data byte or unit. */
    UNDEFINED
  }
}
