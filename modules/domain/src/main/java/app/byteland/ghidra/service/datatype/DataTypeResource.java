package app.byteland.ghidra.service.datatype;

import java.util.List;

public record DataTypeResource(
    String path,
    String name,
    String categoryPath,
    Kind kind,
    Integer length,
    String description,
    Integer size,
    List<Field> fields,
    List<EnumValue> values,
    FunctionSignature signature,
    DataTypeReference baseType) {
  public DataTypeResource {
    fields = immutableCopyOrNull(fields);
    values = immutableCopyOrNull(values);
  }

  @Override
  public List<Field> fields() {
    return immutableCopyOrNull(fields);
  }

  @Override
  public List<EnumValue> values() {
    return immutableCopyOrNull(values);
  }

  private static <T> List<T> immutableCopyOrNull(List<T> values) {
    return values == null ? null : List.copyOf(values);
  }

  public enum Kind {
    STRUCT,
    ENUM,
    TYPEDEF,
    UNION,
    POINTER,
    ARRAY,
    FUNCTION,
    BUILTIN,
    OTHER
  }

  public record Field(
      int ordinal,
      String name,
      int offset,
      int endOffset,
      Kind kind,
      int length,
      String comment,
      boolean isUndefined,
      DataTypeReference dataType) {}

  public record EnumValue(String name, long value, String comment) {}
}
