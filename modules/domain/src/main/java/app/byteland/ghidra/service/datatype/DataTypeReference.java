package app.byteland.ghidra.service.datatype;

import java.nio.charset.StandardCharsets;
import java.util.Objects;

public sealed interface DataTypeReference
    permits DataTypeReference.Named,
        DataTypeReference.Pointer,
        DataTypeReference.Array,
        DataTypeReference.UntypedPointer,
        DataTypeReference.CExpression {

  /** Maximum UTF-8 byte length accepted for a C data type expression. */
  int MAX_EXPRESSION_BYTES = 4_096;

  String kind();

  record Named(String name) implements DataTypeReference {
    public Named {
      name = requiredText(name, "name");
    }

    @Override
    public String kind() {
      return "named";
    }
  }

  record Pointer(DataTypeReference target) implements DataTypeReference {
    public Pointer {
      Objects.requireNonNull(target, "target");
    }

    @Override
    public String kind() {
      return "pointer";
    }
  }

  record Array(DataTypeReference element, int count) implements DataTypeReference {
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

  record UntypedPointer() implements DataTypeReference {
    @Override
    public String kind() {
      return "untyped_pointer";
    }
  }

  record CExpression(String expression) implements DataTypeReference {
    public CExpression {
      expression = requiredExpression(expression);
    }

    @Override
    public String kind() {
      return "c_expression";
    }
  }

  static DataTypeReference named(String name) {
    return new Named(name);
  }

  static DataTypeReference pointerTo(DataTypeReference target) {
    return new Pointer(target);
  }

  static DataTypeReference arrayOf(DataTypeReference element, int count) {
    return new Array(element, count);
  }

  static DataTypeReference untypedPointer() {
    return new UntypedPointer();
  }

  static DataTypeReference cExpression(String expression) {
    return new CExpression(expression);
  }

  private static String requiredExpression(String value) {
    if (value == null) {
      throw new IllegalArgumentException("expression must be a non-empty string");
    }
    if (value.length() > MAX_EXPRESSION_BYTES
        || value.getBytes(StandardCharsets.UTF_8).length > MAX_EXPRESSION_BYTES) {
      throw new IllegalArgumentException(
          "C data type expression exceeds maximum size of "
              + MAX_EXPRESSION_BYTES
              + " UTF-8 bytes");
    }
    if (value.isBlank()) {
      throw new IllegalArgumentException("expression must be a non-empty string");
    }
    return value.trim();
  }

  private static String requiredText(String value, String field) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException(field + " must be a non-empty string");
    }
    return value.trim();
  }
}
