package app.byteland.ghidra.service.function;

import java.util.Objects;

public sealed interface VariableStorageReference
    permits VariableStorageReference.Serialization, VariableStorageReference.Register {
  String kind();

  static VariableStorageReference serialization(String value) {
    return new Serialization(value);
  }

  static VariableStorageReference register(String value) {
    return new Register(value);
  }

  record Serialization(String serialization) implements VariableStorageReference {
    public Serialization {
      serialization = requireText(serialization, "serialization");
    }

    @Override
    public String kind() {
      return "serialization";
    }
  }

  record Register(String register) implements VariableStorageReference {
    public Register {
      register = requireText(register, "register");
    }

    @Override
    public String kind() {
      return "register";
    }
  }

  private static String requireText(String value, String field) {
    String normalized = Objects.requireNonNull(value, field).trim();
    if (normalized.isEmpty()) {
      throw new IllegalArgumentException(field + " must not be empty");
    }
    return normalized;
  }
}
