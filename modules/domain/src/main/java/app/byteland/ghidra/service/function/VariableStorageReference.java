package app.byteland.ghidra.service.function;

import java.util.Objects;

/**
 * References custom variable or return storage by Ghidra serialization text or register name.
 */
public sealed interface VariableStorageReference
    permits VariableStorageReference.Serialization, VariableStorageReference.Register {
  /**
   * Returns the wire discriminator kind for this storage reference.
   *
   * @return storage reference kind identifier
   */
  String kind();

  /**
   * Creates a storage reference from a Ghidra variable storage serialization string.
   *
   * @param value non-empty storage serialization text
   * @return serialization storage reference
   */
  static VariableStorageReference serialization(String value) {
    return new Serialization(value);
  }

  /**
   * Creates a storage reference from an architectural register name.
   *
   * @param value non-empty register name
   * @return register storage reference
   */
  static VariableStorageReference register(String value) {
    return new Register(value);
  }

  /**
   * Variable storage specified by Ghidra serialization syntax.
   *
   * @param serialization trimmed storage serialization string
   */
  record Serialization(String serialization) implements VariableStorageReference {
    /** Validates and trims the serialization string. */
    public Serialization {
      serialization = requireText(serialization, "serialization");
    }

    @Override
    public String kind() {
      return "serialization";
    }
  }

  /**
   * Variable storage specified by processor register name.
   *
   * @param register trimmed processor register name
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
