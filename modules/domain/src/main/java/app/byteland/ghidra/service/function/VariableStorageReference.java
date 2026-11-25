package app.byteland.ghidra.service.function;

import java.util.Objects;

/** Storage location specification for a function return value, parameter, or variable. */
public sealed interface VariableStorageReference
    permits VariableStorageReference.Serialization, VariableStorageReference.Register {
  /**
   * Returns the wire kind discriminator for this storage reference.
   *
   * @return storage reference kind
   */
  String kind();

  /**
   * Creates a storage reference from a Ghidra variable storage serialization string.
   *
   * @param value storage serialization text
   * @return serialization storage reference
   */
  static VariableStorageReference serialization(String value) {
    return new Serialization(value);
  }

  /**
   * Creates a storage reference targeting an architectural register name.
   *
   * @param value register name
   * @return register storage reference
   */
  static VariableStorageReference register(String value) {
    return new Register(value);
  }

  /**
   * Variable storage specified via Ghidra's serialized varnode list syntax.
   *
   * @param serialization non-empty serialized storage string
   */
  record Serialization(String serialization) implements VariableStorageReference {
    /** Validates and trims {@code serialization}. */
    public Serialization {
      serialization = requireText(serialization, "serialization");
    }

    @Override
    public String kind() {
      return "serialization";
    }
  }

  /**
   * Variable storage specified by architectural register name.
   *
   * @param register non-empty register name
   */
  record Register(String register) implements VariableStorageReference {
    /** Validates and trims {@code register}. */
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
