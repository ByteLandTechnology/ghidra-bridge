package app.byteland.ghidra.service.datatype;

import java.util.List;

/**
 * Describes a Ghidra data type and its optional composite, enum, typedef, or function details.
 *
 * @param path absolute data type path
 * @param name simple data type name
 * @param categoryPath parent category path
 * @param kind high-level data type classification
 * @param length reported Ghidra byte length, or {@code null}
 * @param description optional data type description
 * @param size concrete byte size for sized types, or {@code null}
 * @param fields composite member list for structs and unions, or {@code null}
 * @param values enum constant list for enums, or {@code null}
 * @param signature function definition signature, or {@code null}
 * @param baseType target type reference for typedefs and pointers, or {@code null}
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
  /** Copies optional member lists into immutable lists. */
  public DataTypeResource {
    fields = immutableCopyOrNull(fields);
    values = immutableCopyOrNull(values);
  }

  /**
   * Returns the composite member list for structure and union data types.
   *
   * @return immutable member list, or {@code null}
   */
  @Override
  public List<Field> fields() {
    return immutableCopyOrNull(fields);
  }

  /**
   * Returns the constant member list for enumeration data types.
   *
   * @return immutable enum value list, or {@code null}
   */
  @Override
  public List<EnumValue> values() {
    return immutableCopyOrNull(values);
  }

  private static <T> List<T> immutableCopyOrNull(List<T> values) {
    return values == null ? null : List.copyOf(values);
  }

  /**
   * High-level classification of a Ghidra data type.
   */
  public enum Kind {
    /** Structure composite type. */
    STRUCT,
    /** Enumeration constant type. */
    ENUM,
    /** Type alias definition. */
    TYPEDEF,
    /** Union composite type. */
    UNION,
    /** Pointer type. */
    POINTER,
    /** Fixed-length array type. */
    ARRAY,
    /** Function definition type. */
    FUNCTION,
    /** Built-in primitive or Ghidra type. */
    BUILTIN,
    /** Unclassified data type. */
    OTHER
  }

  /**
   * Member field of a structure or union data type.
   *
   * @param ordinal zero-based component ordinal
   * @param name field name, or {@code null} when unnamed
   * @param offset byte start offset within the composite
   * @param endOffset inclusive byte end offset within the composite
   * @param kind classification of the field's data type
   * @param length field byte length
   * @param comment optional field comment
   * @param isUndefined {@code true} if the slot holds an undefined filler byte
   * @param dataType structured reference to the field's data type
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
   * Named integer constant of an enumeration data type.
   *
   * @param name constant member name
   * @param value integer constant value
   * @param comment optional member comment
   */
  public record EnumValue(String name, long value, String comment) {}
}
