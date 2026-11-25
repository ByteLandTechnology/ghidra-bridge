package app.byteland.ghidra.service.function;

import java.util.Objects;

/**
 * Custom variable storage specification by Ghidra serialization string or register name.
 */
public sealed interface VariableStorageReference
    permits VariableStorageReference.Serialization, VariableStorageReference.Register {
  /**
   * Returns the storage reference kind identifier.
   *
   * @return {@code "serialization"} or {@code "register"}
   */
  String kind();

  /**
   * Creates a variable storage reference from a Ghidra storage serialization string.
   *
   * @param value storage serialization string
   * @return serialization variable storage reference
   */
  static VariableStorageReference serialization(String value) {
    return new Serialization(value);
  }

  /**
   * Creates a variable storage reference from an architecture register name.
   *
   * @param value register name
   * @return register variable storage reference
   */
  static VariableStorageReference register(String value) {
    return new Register(value);
  }

  /**
   * Variable storage identified by a Ghidra serialization string.
   *
   * @param serialization Ghidra variable storage serialization text
   */
  record Serialization(String serialization) implements VariableStorageReference {
    /** Validates and trims the serialization text. */
    public Serialization {
      serialization = requireText(serialization, "serialization");
    }

    @Override
    public String kind() {
      return "serialization";
    }
  }

  /**
   * Variable storage identified by a processor register name.
   *
   * @param register processor register name
   */
  record Register(String register) implements VariableStorageReference {
    /** Validates and trims the register name. */
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
