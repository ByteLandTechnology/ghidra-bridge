package app.byteland.ghidra.service.datatype;

import java.util.Objects;

public sealed interface DataTypeReference
    permits DataTypeReference.Named,
        DataTypeReference.Pointer,
        DataTypeReference.Array,
        DataTypeReference.UntypedPointer,
        DataTypeReference.CExpression {

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
      expression = requiredText(expression, "expression");
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

  private static String requiredText(String value, String field) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException(field + " must be a non-empty string");
    }
    return value.trim();
  }
}
