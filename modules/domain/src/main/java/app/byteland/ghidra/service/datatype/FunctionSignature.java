package app.byteland.ghidra.service.datatype;

import java.util.List;

/**
 * Represents a function definition signature with return type, parameters, and calling convention.
 *
 * @param returnType non-null return data type reference
 * @param parameters ordered parameter definitions
 * @param callingConvention explicit non-unknown calling convention name
 * @param hasVarArgs true when the signature accepts variadic arguments
 * @param hasNoReturn true when the function does not return
 */
public record FunctionSignature(
    DataTypeReference returnType,
    List<Parameter> parameters,
    String callingConvention,
    boolean hasVarArgs,
    boolean hasNoReturn) {
  private static final String UNKNOWN_CALLING_CONVENTION = "unknown";

  /** Validates return type, parameters, and calling convention invariants. */
  public FunctionSignature {
    if (returnType == null) {
      throw new IllegalArgumentException("function signature returnType is required");
    }
    if (parameters == null) {
      throw new IllegalArgumentException("function signature parameters are required");
    }
    for (int index = 0; index < parameters.size(); index++) {
      if (parameters.get(index) == null) {
        throw new IllegalArgumentException(
            "function signature parameters[" + index + "] is required");
      }
    }
    parameters = List.copyOf(parameters);
    if (callingConvention == null || callingConvention.isBlank()) {
      throw new IllegalArgumentException("function signature callingConvention is required");
    }
    callingConvention = callingConvention.trim();
    if (UNKNOWN_CALLING_CONVENTION.equalsIgnoreCase(callingConvention)) {
      throw new IllegalArgumentException(
          "function signature callingConvention must not be unknown");
    }
  }

  /**
   * Describes one formal parameter in a function definition signature.
   *
   * @param name optional normalized parameter name
   * @param dataType non-null parameter data type reference
   */
  public record Parameter(String name, DataTypeReference dataType) {
    /** Normalizes optional parameter name and validates required data type. */
    public Parameter {
      name = emptyToNull(name);
      if (dataType == null) {
        throw new IllegalArgumentException("function parameter dataType is required");
      }
    }
  }

  private static String emptyToNull(String value) {
    if (value == null) return null;
    String normalized = value.trim();
    return normalized.isEmpty() ? null : normalized;
  }
}
