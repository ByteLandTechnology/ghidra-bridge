package app.byteland.ghidra.service.listing;

import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import java.util.List;

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
  public CodeUnitResource {
    operands = immutableCopyOrNull(operands);
  }

  @Override
  public List<String> operands() {
    return immutableCopyOrNull(operands);
  }

  private static <T> List<T> immutableCopyOrNull(List<T> values) {
    return values == null ? null : List.copyOf(values);
  }

  public enum Kind {
    INSTRUCTION,
    DATA,
    UNDEFINED
  }
}
