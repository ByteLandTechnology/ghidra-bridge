package app.byteland.ghidra.service.listing;

import app.byteland.ghidra.service.ByteSequence;
import java.util.List;

/**
 * Disassembled instruction metadata, bytes, operands, and control-flow details.
 *
 * @param address canonical instruction start address
 * @param length byte length of the instruction
 * @param bytes raw instruction bytes when available
 * @param mnemonic instruction mnemonic
 * @param operands formatted operand strings
 * @param flowOverride active flow override value
 * @param defaultFlowType processor default flow type name
 * @param flowType effective flow type name
 * @param fallThrough fall-through address when present
 */
public record InstructionResource(
    String address,
    int length,
    ByteSequence bytes,
    String mnemonic,
    List<String> operands,
    FlowOverrideValue flowOverride,
    String defaultFlowType,
    String flowType,
    String fallThrough) {
  /** Copies non-null operand lists into an immutable collection. */
  public InstructionResource {
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
}
