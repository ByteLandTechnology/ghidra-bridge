package app.byteland.ghidra.service.datatype;

import java.util.List;

/**
 * Snapshot of a Ghidra data type definition.
 *
 * @param path full data type path
 * @param name data type short name
 * @param categoryPath parent category path
 * @param kind high-level data type classification
 * @param length byte length when fixed-length, or {@code null}
 * @param description human-readable description
 * @param size enum byte size when applicable, or {@code null}
 * @param fields composite fields for struct or union types, or {@code null}
 * @param values enum members for enum types, or {@code null}
 * @param signature function definition signature for function types, or {@code null}
 * @param baseType underlying target or base type for typedef, pointer, or array types
 */
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
  /** Defensively copies non-null member lists. */
  public DataTypeResource {
    fields = immutableCopyOrNull(fields);
    values = immutableCopyOrNull(values);
  }

  /**
   * Returns composite fields for struct or union types, or {@code null}.
   *
   * @return composite field list, or {@code null}
   */
  @Override
  public List<Field> fields() {
    return immutableCopyOrNull(fields);
  }

  /**
   * Returns enum members for enum types, or {@code null}.
   *
   * @return enum member list, or {@code null}
   */
  @Override
  public List<EnumValue> values() {
    return immutableCopyOrNull(values);
  }

  private static <T> List<T> immutableCopyOrNull(List<T> values) {
    return values == null ? null : List.copyOf(values);
  }

  /** Classification of program data types. */
  public enum Kind {
    /** Structure composite type. */
    STRUCT,
    /** Enumeration type. */
    ENUM,
    /** Type alias definition. */
    TYPEDEF,
    /** Union composite type. */
    UNION,
    /** Pointer type. */
    POINTER,
    /** Fixed-size array type. */
    ARRAY,
    /** Function definition type. */
    FUNCTION,
    /** Built-in primitive or Ghidra type. */
    BUILTIN,
    /** Unclassified data type. */
    OTHER
  }

  /**
   * Component field within a struct or union data type.
   *
   * @param ordinal zero-based component ordinal
   * @param name field name, or {@code null} for unnamed padding
   * @param offset start byte offset within the composite
   * @param endOffset inclusive end byte offset within the composite
   * @param kind component data type classification
   * @param length component byte length
   * @param comment optional field comment
   * @param isUndefined whether the component represents undefined padding
   * @param dataType component data type reference
   */
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

  /**
   * Named constant entry within an enum data type.
   *
   * @param name enum member name
   * @param value numeric value
   * @param comment optional member comment
   */
  public record EnumValue(String name, long value, String comment) {}
}
