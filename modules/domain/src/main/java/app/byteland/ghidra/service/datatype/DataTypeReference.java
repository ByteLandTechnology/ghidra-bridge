package app.byteland.ghidra.service.datatype;

import java.util.Objects;

/**
 * Recursive reference to a named, pointer, array, or untyped-pointer data type.
 */
public sealed interface DataTypeReference
    permits DataTypeReference.Named,
        DataTypeReference.Pointer,
        DataTypeReference.Array,
        DataTypeReference.UntypedPointer {

  /**
   * Returns the wire discriminator string for this reference variant.
   *
   * @return {@code "named"}, {@code "pointer"}, {@code "array"}, or {@code "untyped_pointer"}
   */
  String kind();

  /**
   * Reference to a data type by category path or unqualified name.
   *
   * @param name non-empty category path or type name
   */
  record Named(String name) implements DataTypeReference {
    /** Trims and validates the referenced type name. */
    public Named {
      name = requiredText(name, "name");
    }

    @Override
    public String kind() {
      return "named";
    }
  }

  /**
   * Typed pointer reference to another {@link DataTypeReference}.
   *
   * @param target pointed-to data type reference
   */
  record Pointer(DataTypeReference target) implements DataTypeReference {
    /** Validates that the pointed-to target reference is non-null. */
    public Pointer {
      Objects.requireNonNull(target, "target");
    }

    @Override
    public String kind() {
      return "pointer";
    }
  }

  /**
   * Fixed-count array reference of an element {@link DataTypeReference}.
   *
   * @param element element data type reference
   * @param count positive element count
   */
  record Array(DataTypeReference element, int count) implements DataTypeReference {
    /** Validates the element reference and positive element count. */
    public Array {
      Objects.requireNonNull(element, "element");
      if (count <= 0) {
        throw new IllegalArgumentException("array count must be a positive integer");
      }
    }

    @Override
    public String kind() {
      return "array";
    }
  }

  /**
   * Untyped pointer reference without a target element type.
   */
  record UntypedPointer() implements DataTypeReference {
    @Override
    public String kind() {
      return "untyped_pointer";
    }
  }

  /**
   * Creates a named data type reference.
   *
   * @param name category path or simple type name
   * @return named data type reference
   */
  static DataTypeReference named(String name) {
    return new Named(name);
  }

  /**
   * Creates a typed pointer reference to {@code target}.
   *
   * @param target pointed-to data type reference
   * @return pointer data type reference
   */
  static DataTypeReference pointerTo(DataTypeReference target) {
    return new Pointer(target);
  }

  /**
   * Creates a fixed-count array reference of {@code element}.
   *
   * @param element array element data type reference
   * @param count positive element count
   * @return array data type reference
   */
  static DataTypeReference arrayOf(DataTypeReference element, int count) {
    return new Array(element, count);
  }

  /**
   * Creates an untyped pointer reference.
   *
   * @return untyped pointer reference
   */
  static DataTypeReference untypedPointer() {
    return new UntypedPointer();
  }

  private static String requiredText(String value, String field) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException(field + " must be a non-empty string");
    }
    return value.trim();
  }
}
