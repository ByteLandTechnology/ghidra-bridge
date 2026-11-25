package app.byteland.ghidra.service.listing;

import app.byteland.ghidra.service.ByteSequence;
import java.util.List;

/**
 * Disassembled instruction metadata in the program listing.
 *
 * @param address instruction start address
 * @param length byte length of the instruction
 * @param bytes raw instruction bytes
 * @param mnemonic instruction mnemonic
 * @param operands formatted operand representations, or {@code null}
 * @param flowOverride active control-flow override value
 * @param defaultFlowType processor default flow type name
 * @param flowType effective flow type name after overrides
 * @param fallThrough fall-through instruction address, or {@code null}
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
  /** Defensively copies non-null {@code operands}. */
  public InstructionResource {
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
}
