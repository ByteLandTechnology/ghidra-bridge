package app.byteland.ghidra.service.listing;

import app.byteland.ghidra.service.ByteSequence;
import java.util.List;

/**
 * Represents a disassembled machine instruction and its control-flow properties.
 *
 * @param address canonical instruction address
 * @param length instruction length in bytes
 * @param bytes raw instruction byte sequence
 * @param mnemonic instruction mnemonic text
 * @param operands rendered operand strings
 * @param flowOverride active control-flow override value
 * @param defaultFlowType processor default flow type name
 * @param flowType effective flow type name
 * @param fallThrough optional fall-through address
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
  /** Copies operand strings into an immutable list when present. */
  public InstructionResource {
    operands = immutableCopyOrNull(operands);
  }

  /**
   * Returns an immutable copy of rendered operand strings, or null when absent.
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
}
