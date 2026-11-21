package app.byteland.ghidra.service.datatype;

import java.util.List;

/**
 * Describes the signature of a function definition data type.
 *
 * @param returnType function return data type reference
 * @param parameters ordered list of formal parameters
 * @param callingConvention non-blank call convention name
 * @param hasVarArgs {@code true} if the function accepts variable arguments
 * @param hasNoReturn {@code true} if the function does not return
 */
public record FunctionSignature(
    DataTypeReference returnType,
    List<Parameter> parameters,
    String callingConvention,
    boolean hasVarArgs,
    boolean hasNoReturn) {
  private static final String UNKNOWN_CALLING_CONVENTION = "unknown";

  /** Validates return type, parameters, and call convention invariants. */
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
   * Formal parameter of a {@link FunctionSignature}.
   *
   * @param name optional parameter name, normalized to {@code null} when blank
   * @param dataType parameter data type reference
   */
  public record Parameter(String name, DataTypeReference dataType) {
    /** Normalizes the parameter name and requires a non-null data type. */
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
