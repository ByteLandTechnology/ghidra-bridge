package app.byteland.ghidra.service.datatype;

import java.util.List;

/**
 * Program data type definition and optional structural details.
 *
 * @param path canonical archive path
 * @param name data type name
 * @param categoryPath parent category path
 * @param kind high-level data type classification
 * @param length fixed byte length when defined
 * @param description optional summary description
 * @param size member storage size for enumerations when defined
 * @param fields composite fields when projected
 * @param values enumeration members when projected
 * @param signature function definition signature when applicable
 * @param baseType underlying typedef target when applicable
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
  /** Copies non-null member lists into immutable collections. */
  public DataTypeResource {
    fields = immutableCopyOrNull(fields);
    values = immutableCopyOrNull(values);
  }

  /**
   * Returns an immutable copy of the projected composite fields.
   *
   * @return composite fields or {@code null}
   */
  @Override
  public List<Field> fields() {
    return immutableCopyOrNull(fields);
  }

  /**
   * Returns an immutable copy of the projected enumeration values.
   *
   * @return enumeration values or {@code null}
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
    /** Fixed-length array type. */
    ARRAY,
    /** Function definition signature type. */
    FUNCTION,
    /** Built-in primitive or intrinsic type. */
    BUILTIN,
    /** Other Ghidra data type kind. */
    OTHER
  }

  /**
   * Field descriptor in a structure or union data type.
   *
   * @param ordinal zero-based component ordinal
   * @param name field name when assigned
   * @param offset starting byte offset
   * @param endOffset inclusive ending byte offset
   * @param kind field data type kind
   * @param length field byte length
   * @param comment optional field comment
   * @param isUndefined whether the component represents undefined padding
   * @param dataType field data type reference
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
   * Member descriptor in an enumeration data type.
   *
   * @param name member name
   * @param value numeric member value
   * @param comment optional member comment
   */
  public record EnumValue(String name, long value, String comment) {}
}
