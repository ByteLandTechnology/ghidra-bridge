package app.byteland.ghidra.service.datatype;

import java.util.Objects;

/**
 * Structural reference to a named, pointer, or array data type.
 */
public sealed interface DataTypeReference
    permits DataTypeReference.Named,
        DataTypeReference.Pointer,
        DataTypeReference.Array,
        DataTypeReference.UntypedPointer {

  /**
   * Returns the reference kind identifier.
   *
   * @return reference kind string
   */
  String kind();

  /**
   * Reference to a data type by name or archive path.
   *
   * @param name data type name or path
   */
  record Named(String name) implements DataTypeReference {
    /** Validates and trims the data type name. */
    public Named {
      name = requiredText(name, "name");
    }

    @Override
    public String kind() {
      return "named";
    }
  }

  /**
   * Reference to a typed pointer data type.
   *
   * @param target pointed-to data type reference
   */
  record Pointer(DataTypeReference target) implements DataTypeReference {
    /** Validates that the pointed-to target reference is present. */
    public Pointer {
      Objects.requireNonNull(target, "target");
    }

    @Override
    public String kind() {
      return "pointer";
    }
  }

  /**
   * Reference to a fixed-count array data type.
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
   * Reference to an untyped pointer data type.
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
   * @param name data type name or path
   * @return named data type reference
   */
  static DataTypeReference named(String name) {
    return new Named(name);
  }

  /**
   * Creates a typed pointer data type reference.
   *
   * @param target pointed-to data type reference
   * @return pointer data type reference
   */
  static DataTypeReference pointerTo(DataTypeReference target) {
    return new Pointer(target);
  }

  /**
   * Creates an array data type reference.
   *
   * @param element element data type reference
   * @param count positive element count
   * @return array data type reference
   */
  static DataTypeReference arrayOf(DataTypeReference element, int count) {
    return new Array(element, count);
  }

  /**
   * Creates an untyped pointer data type reference.
   *
   * @return untyped pointer data type reference
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
