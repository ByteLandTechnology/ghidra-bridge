package app.byteland.ghidra.service.function;

import java.util.Objects;

/**
 * Identifies custom variable storage by Ghidra storage serialization or register name.
 */
public sealed interface VariableStorageReference
    permits VariableStorageReference.Serialization, VariableStorageReference.Register {
  /**
   * Returns the wire discriminator string for this storage reference variant.
   *
   * @return {@code "serialization"} or {@code "register"}
   */
  String kind();

  /**
   * Creates a storage reference from a Ghidra variable storage serialization string.
   *
   * @param value non-empty storage serialization string
   * @return serialization storage reference
   */
  static VariableStorageReference serialization(String value) {
    return new Serialization(value);
  }

  /**
   * Creates a storage reference from a processor register name.
   *
   * @param value non-empty register name
   * @return register storage reference
   */
  static VariableStorageReference register(String value) {
    return new Register(value);
  }

  /**
   * Variable storage specified as a Ghidra serialization string.
   *
   * @param serialization non-empty Ghidra storage serialization string
   */
  record Serialization(String serialization) implements VariableStorageReference {
    /** Trims and validates the storage serialization string. */
    public Serialization {
      serialization = requireText(serialization, "serialization");
    }

    @Override
    public String kind() {
      return "serialization";
    }
  }

  /**
   * Variable storage specified as a named processor register.
   *
   * @param register non-empty processor register name
   */
  record Register(String register) implements VariableStorageReference {
    /** Trims and validates the register name. */
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
