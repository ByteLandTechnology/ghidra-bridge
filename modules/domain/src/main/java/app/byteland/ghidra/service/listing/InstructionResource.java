package app.byteland.ghidra.service.listing;

import app.byteland.ghidra.service.ByteSequence;
import java.util.List;

public record InstructionResource(
    String address,
    int length,
    ByteSequence bytes,
    String mnemonic,
    List<String> operands,
    FlowOverrideValue flowOverride,
    String defaultFlowType,
    String flowType,
    String fallThrough,
    List<String> flows) {
  public InstructionResource {
    operands = immutableCopyOrNull(operands);
    flows = immutableCopyOrNull(flows);
  }

  public InstructionResource(
      String address,
      int length,
      ByteSequence bytes,
      String mnemonic,
      List<String> operands,
      FlowOverrideValue flowOverride,
      String defaultFlowType,
      String flowType,
      String fallThrough) {
    this(
        address,
        length,
        bytes,
        mnemonic,
        operands,
        flowOverride,
        defaultFlowType,
        flowType,
        fallThrough,
        List.of());
  }

  @Override
  public List<String> operands() {
    return immutableCopyOrNull(operands);
  }

  @Override
  public List<String> flows() {
    return immutableCopyOrNull(flows);
  }

  private static <T> List<T> immutableCopyOrNull(List<T> values) {
    return values == null ? null : List.copyOf(values);
  }
}
