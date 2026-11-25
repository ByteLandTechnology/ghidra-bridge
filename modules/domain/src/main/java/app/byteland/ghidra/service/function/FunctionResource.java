package app.byteland.ghidra.service.function;

import app.byteland.ghidra.service.datatype.DataTypeReference;
import java.util.List;

/**
 * Snapshot of a program function and optional projected details.
 *
 * @param entry function entry point address
 * @param name function name
 * @param namespace enclosing namespace path
 * @param body address bounds of the function body, or {@code null}
 * @param signature formatted prototype string
 * @param returnType return data type reference
 * @param returnStorage return value storage location, or {@code null}
 * @param parameterCount number of formal parameters
 * @param callingConvention calling convention name
 * @param parameters projected formal parameters, or {@code null} when omitted
 * @param localVariables projected local variables, or {@code null} when omitted
 * @param comment plate or function comment, or {@code null}
 * @param isInline whether the function is marked inline
 * @param hasNoReturn whether the function is marked non-returning
 * @param hasVarArgs whether the function accepts variadic arguments
 * @param hasCustomVariableStorage whether custom variable storage is enabled
 * @param stackPurgeSize stack purge size in bytes, or {@code null}
 * @param external whether the function is external
 * @param thunk whether the function is a thunk
 * @param repeatableComment repeatable function comment, or {@code null}
 * @param tags projected function tags, or {@code null} when omitted
 * @param demangledName demangled function name, or {@code null}
 */
public record FunctionResource(
    String entry,
    String name,
    String namespace,
    Body body,
    String signature,
    DataTypeReference returnType,
    VariableStorageReference returnStorage,
    int parameterCount,
    String callingConvention,
    List<ParameterResource> parameters,
    List<LocalVariableResource> localVariables,
    String comment,
    boolean isInline,
    boolean hasNoReturn,
    boolean hasVarArgs,
    boolean hasCustomVariableStorage,
    Integer stackPurgeSize,
    boolean external,
    boolean thunk,
    String repeatableComment,
    List<String> tags,
    String demangledName) {
  /** Defensively copies non-null projected lists. */
  public FunctionResource {
    parameters = immutableCopyOrNull(parameters);
    localVariables = immutableCopyOrNull(localVariables);
    tags = immutableCopyOrNull(tags);
  }

  /**
   * Returns projected formal parameters, or {@code null} when omitted.
   *
   * @return formal parameter list, or {@code null}
   */
  @Override
  public List<ParameterResource> parameters() {
    return immutableCopyOrNull(parameters);
  }

  /**
   * Returns projected local variables, or {@code null} when omitted.
   *
   * @return local variable list, or {@code null}
   */
  @Override
  public List<LocalVariableResource> localVariables() {
    return immutableCopyOrNull(localVariables);
  }

  /**
   * Returns projected function tags, or {@code null} when omitted.
   *
   * @return function tag list, or {@code null}
   */
  @Override
  public List<String> tags() {
    return immutableCopyOrNull(tags);
  }

  private static <T> List<T> immutableCopyOrNull(List<T> values) {
    return values == null ? null : List.copyOf(values);
  }

  /**
   * Address span summary of a function body.
   *
   * @param start minimum address in the function body
   * @param end maximum address in the function body
   * @param numAddresses total number of addresses in the body
   */
  public record Body(String start, String end, long numAddresses) {}

  /**
   * Formal parameter metadata for a function.
   *
   * @param ordinal zero-based parameter ordinal
   * @param name parameter name
   * @param dataType parameter data type reference
   * @param storage parameter storage location, or {@code null}
   */
  public record ParameterResource(
      int ordinal, String name, DataTypeReference dataType, VariableStorageReference storage) {}

  /**
   * Local variable metadata for a function.
   *
   * @param name local variable name
   * @param dataType local variable data type reference
   * @param storage variable storage location, or {@code null}
   */
  public record LocalVariableResource(
      String name, DataTypeReference dataType, VariableStorageReference storage) {}
}
