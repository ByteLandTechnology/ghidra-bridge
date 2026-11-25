package app.byteland.ghidra.service.datatype;

import java.util.List;

/**
 * Signature specification for a function definition data type.
 *
 * @param returnType return data type reference
 * @param parameters ordered parameter definitions
 * @param callingConvention calling convention name
 * @param hasVarArgs whether the signature accepts variadic arguments
 * @param hasNoReturn whether the function does not return
 */
public record FunctionSignature(
    DataTypeReference returnType,
    List<Parameter> parameters,
    String callingConvention,
    boolean hasVarArgs,
    boolean hasNoReturn) {
  private static final String UNKNOWN_CALLING_CONVENTION = "unknown";

  /** Validates signature fields and copies parameters into an immutable list. */
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
   * Parameter definition in a function signature.
   *
   * @param name optional parameter name
   * @param dataType parameter data type reference
   */
  public record Parameter(String name, DataTypeReference dataType) {
    /** Normalizes blank names to {@code null} and requires a data type. */
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
