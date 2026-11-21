package app.byteland.ghidra.service.datatype;

import java.util.List;

/**
 * Describes a Ghidra data type definition and its members or signature.
 *
 * @param path absolute data type path
 * @param name data type name
 * @param categoryPath parent category path
 * @param kind data type classification
 * @param length fixed length in bytes when defined
 * @param description optional data type description
 * @param size enumeration width in bytes when applicable
 * @param fields structure or union field definitions
 * @param values enumeration constant definitions
 * @param signature function definition signature when applicable
 * @param baseType underlying typedef, pointer, or array target type when applicable
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
  /** Copies member lists into immutable lists when present. */
  public DataTypeResource {
    fields = immutableCopyOrNull(fields);
    values = immutableCopyOrNull(values);
  }

  /**
   * Returns an immutable copy of composite fields, or null when absent.
   *
   * @return immutable field list or null
   */
  @Override
  public List<Field> fields() {
    return immutableCopyOrNull(fields);
  }

  /**
   * Returns an immutable copy of enumeration constants, or null when absent.
   *
   * @return immutable enumeration constant list or null
   */
  @Override
  public List<EnumValue> values() {
    return immutableCopyOrNull(values);
  }

  private static <T> List<T> immutableCopyOrNull(List<T> values) {
    return values == null ? null : List.copyOf(values);
  }

  /** Classification of Ghidra data types. */
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
    /** Function signature definition type. */
    FUNCTION,
    /** Built-in primitive or dynamic type. */
    BUILTIN,
    /** Unclassified data type. */
    OTHER
  }

  /**
   * Describes one component field in a structure or union data type.
   *
   * @param ordinal zero-based component ordinal
   * @param name optional component field name
   * @param offset start byte offset
   * @param endOffset inclusive end byte offset
   * @param kind field data type classification
   * @param length component byte length
   * @param comment optional field comment
   * @param isUndefined true when the component is an undefined filler slot
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
   * Describes one named constant in an enumeration data type.
   *
   * @param name enumeration constant name
   * @param value numeric constant value
   * @param comment optional constant comment
   */
  public record EnumValue(String name, long value, String comment) {}
}
