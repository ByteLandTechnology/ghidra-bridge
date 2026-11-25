package app.byteland.ghidra.service.function;

import app.byteland.ghidra.service.datatype.DataTypeReference;
import java.util.List;

/**
 * Program function metadata, signature, storage, and optional local details.
 *
 * @param entry canonical function entry address
 * @param name function name
 * @param namespace function namespace path
 * @param body contiguous or aggregate body bounds
 * @param signature formatted signature string
 * @param returnType return data type reference
 * @param returnStorage return value storage when custom storage is active
 * @param parameterCount number of formal parameters
 * @param callingConvention calling convention name
 * @param parameters projected parameter list when requested
 * @param localVariables projected local variable list when requested
 * @param comment plate comment when projected
 * @param isInline whether the function is marked inline
 * @param hasNoReturn whether the function is marked non-returning
 * @param hasVarArgs whether the function accepts variadic arguments
 * @param hasCustomVariableStorage whether custom parameter and return storage is enabled
 * @param stackPurgeSize stack purge byte delta when known
 * @param external whether the function is external
 * @param thunk whether the function is a thunk
 * @param repeatableComment repeatable comment when projected
 * @param tags function tag names when projected
 * @param demangledName optional demangled function name
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
  /** Copies non-null projected lists into immutable collections. */
  public FunctionResource {
    parameters = immutableCopyOrNull(parameters);
    localVariables = immutableCopyOrNull(localVariables);
    tags = immutableCopyOrNull(tags);
  }

  /**
   * Returns an immutable copy of the projected parameter list.
   *
   * @return formal parameters or {@code null}
   */
  @Override
  public List<ParameterResource> parameters() {
    return immutableCopyOrNull(parameters);
  }

  /**
   * Returns an immutable copy of the projected local variable list.
   *
   * @return local variables or {@code null}
   */
  @Override
  public List<LocalVariableResource> localVariables() {
    return immutableCopyOrNull(localVariables);
  }

  /**
   * Returns an immutable copy of the projected function tags.
   *
   * @return function tag names or {@code null}
   */
  @Override
  public List<String> tags() {
    return immutableCopyOrNull(tags);
  }

  private static <T> List<T> immutableCopyOrNull(List<T> values) {
    return values == null ? null : List.copyOf(values);
  }

  /**
   * Address bounds summary for a function body.
   *
   * @param start minimum body address
   * @param end maximum body address
   * @param numAddresses total number of addresses in the body set
   */
  public record Body(String start, String end, long numAddresses) {}

  /**
   * Formal parameter descriptor for a function.
   *
   * @param ordinal zero-based parameter ordinal
   * @param name parameter name
   * @param dataType parameter data type reference
   * @param storage optional parameter variable storage
   */
  public record ParameterResource(
      int ordinal, String name, DataTypeReference dataType, VariableStorageReference storage) {}

  /**
   * Local variable descriptor for a function.
   *
   * @param name local variable name
   * @param dataType variable data type reference
   * @param storage variable storage location
   */
  public record LocalVariableResource(
      String name, DataTypeReference dataType, VariableStorageReference storage) {}
}
