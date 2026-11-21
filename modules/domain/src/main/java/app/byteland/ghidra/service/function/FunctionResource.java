package app.byteland.ghidra.service.function;

import app.byteland.ghidra.service.datatype.DataTypeReference;
import java.util.List;

/**
 * Represents a Ghidra function metadata, signature, variables, and attributes.
 *
 * @param entry function entry point address
 * @param name function name
 * @param namespace parent namespace path
 * @param body address span of the function body
 * @param signature formatted signature string when projected
 * @param returnType return data type reference when projected
 * @param returnStorage return storage location when projected
 * @param parameterCount formal parameter count
 * @param callingConvention calling convention name
 * @param parameters formal parameter list when projected
 * @param localVariables local variable list when projected
 * @param comment optional plate comment text when projected
 * @param isInline true when marked inline
 * @param hasNoReturn true when marked no-return
 * @param hasVarArgs true when marked variadic
 * @param hasCustomVariableStorage true when custom variable storage is enabled
 * @param stackPurgeSize optional stack purge size in bytes
 * @param external true when the function is external
 * @param thunk true when the function is a thunk
 * @param repeatableComment optional repeatable comment when projected
 * @param tags function tag names when projected
 * @param demangledName optional demangled C++ name
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
  /** Copies projected list components into immutable lists when present. */
  public FunctionResource {
    parameters = immutableCopyOrNull(parameters);
    localVariables = immutableCopyOrNull(localVariables);
    tags = immutableCopyOrNull(tags);
  }

  /**
   * Returns an immutable copy of formal parameters, or null when omitted.
   *
   * @return immutable parameter list or null
   */
  @Override
  public List<ParameterResource> parameters() {
    return immutableCopyOrNull(parameters);
  }

  /**
   * Returns an immutable copy of local variables, or null when omitted.
   *
   * @return immutable local variable list or null
   */
  @Override
  public List<LocalVariableResource> localVariables() {
    return immutableCopyOrNull(localVariables);
  }

  /**
   * Returns an immutable copy of function tag names, or null when omitted.
   *
   * @return immutable tag list or null
   */
  @Override
  public List<String> tags() {
    return immutableCopyOrNull(tags);
  }

  private static <T> List<T> immutableCopyOrNull(List<T> values) {
    return values == null ? null : List.copyOf(values);
  }

  /**
   * Summarizes the address span and size of a function body.
   *
   * @param start minimum address in the body
   * @param end maximum address in the body
   * @param numAddresses total address count in the body
   */
  public record Body(String start, String end, long numAddresses) {}

  /**
   * Describes one formal parameter of a function.
   *
   * @param ordinal zero-based parameter ordinal
   * @param name parameter name
   * @param dataType parameter data type reference
   * @param storage parameter storage location
   */
  public record ParameterResource(
      int ordinal, String name, DataTypeReference dataType, VariableStorageReference storage) {}

  /**
   * Describes one local variable of a function.
   *
   * @param name local variable name
   * @param dataType variable data type reference
   * @param storage variable storage location
   */
  public record LocalVariableResource(
      String name, DataTypeReference dataType, VariableStorageReference storage) {}
}
