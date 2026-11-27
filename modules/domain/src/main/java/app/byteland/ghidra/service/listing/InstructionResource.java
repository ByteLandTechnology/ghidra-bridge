package app.byteland.ghidra.service.listing;

import app.byteland.ghidra.service.ByteSequence;
import java.util.List;

/**
 * Describes a disassembled machine instruction and its control-flow metadata.
 *
 * @param address canonical instruction address
 * @param length instruction byte length
 * @param bytes raw instruction bytes
 * @param mnemonic instruction mnemonic text
 * @param operands rendered operand strings
 * @param flowOverride configured flow override value
 * @param defaultFlowType processor default flow type name
 * @param flowType effective flow type name
 * @param fallThrough canonical fall-through address, or {@code null}
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
  /** Copies optional operand strings into an immutable list. */
  public InstructionResource {
    operands = immutableCopyOrNull(operands);
  }

  /**
   * Returns the rendered operand strings for this instruction.
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
}
