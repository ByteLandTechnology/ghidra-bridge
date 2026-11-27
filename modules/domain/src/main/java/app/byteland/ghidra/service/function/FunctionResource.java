package app.byteland.ghidra.service.function;

import app.byteland.ghidra.service.datatype.DataTypeReference;
import java.util.List;

/**
 * Describes a Ghidra function, its signature, body bounds, and optional variables and comments.
 *
 * @param entry canonical entry-point address
 * @param name function name
 * @param namespace parent namespace name
 * @param body address bounds and size of the function body, or {@code null}
 * @param signature formatted C prototype string
 * @param returnType return data type reference
 * @param returnStorage return value storage location, or {@code null}
 * @param parameterCount formal parameter count
 * @param callingConvention call convention name, or {@code null}
 * @param parameters optional formal parameter list when requested
 * @param localVariables optional local variable list when requested
 * @param comment optional plate comment when requested
 * @param isInline {@code true} if marked inline
 * @param hasNoReturn {@code true} if marked no-return
 * @param hasVarArgs {@code true} if the function accepts variable arguments
 * @param hasCustomVariableStorage {@code true} if custom storage is enabled
 * @param stackPurgeSize stack purge byte size, or {@code null} when unknown
 * @param external {@code true} if the function is external
 * @param thunk {@code true} if the function is a thunk
 * @param repeatableComment optional repeatable comment when requested
 * @param tags optional function tag names when requested
 * @param demangledName optional demangled C++ signature, or {@code null}
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
  /** Copies optional parameter, local variable, and tag lists into immutable lists. */
  public FunctionResource {
    parameters = immutableCopyOrNull(parameters);
    localVariables = immutableCopyOrNull(localVariables);
    tags = immutableCopyOrNull(tags);
  }

  /**
   * Returns the formal parameter list when requested in {@code includes}.
   *
   * @return immutable parameter list, or {@code null}
   */
  @Override
  public List<ParameterResource> parameters() {
    return immutableCopyOrNull(parameters);
  }

  /**
   * Returns the local variable list when requested in {@code includes}.
   *
   * @return immutable local variable list, or {@code null}
   */
  @Override
  public List<LocalVariableResource> localVariables() {
    return immutableCopyOrNull(localVariables);
  }

  /**
   * Returns the function tag names when requested in {@code includes}.
   *
   * @return immutable tag name list, or {@code null}
   */
  @Override
  public List<String> tags() {
    return immutableCopyOrNull(tags);
  }

  private static <T> List<T> immutableCopyOrNull(List<T> values) {
    return values == null ? null : List.copyOf(values);
  }

  /**
   * Address bounds and total byte count of a function body.
   *
   * @param start minimum canonical address in the body
   * @param end maximum canonical address in the body
   * @param numAddresses total number of addresses in the body set
   */
  public record Body(String start, String end, long numAddresses) {}

  /**
   * Formal parameter metadata of a {@link FunctionResource}.
   *
   * @param ordinal zero-based parameter ordinal
   * @param name parameter name
   * @param dataType parameter data type reference
   * @param storage parameter storage location, or {@code null}
   */
  public record ParameterResource(
      int ordinal, String name, DataTypeReference dataType, VariableStorageReference storage) {}

  /**
   * Local variable metadata of a {@link FunctionResource}.
   *
   * @param name local variable name
   * @param dataType local variable data type reference
   * @param storage local variable storage location, or {@code null}
   */
  public record LocalVariableResource(
      String name, DataTypeReference dataType, VariableStorageReference storage) {}
}
