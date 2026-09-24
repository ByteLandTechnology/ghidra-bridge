package app.byteland.ghidra.service.function;

import app.byteland.ghidra.service.datatype.DataTypeReference;
import java.util.List;

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
    List<String> tags) {
  public FunctionResource {
    parameters = immutableCopyOrNull(parameters);
    localVariables = immutableCopyOrNull(localVariables);
    tags = immutableCopyOrNull(tags);
  }

  @Override
  public List<ParameterResource> parameters() {
    return immutableCopyOrNull(parameters);
  }

  @Override
  public List<LocalVariableResource> localVariables() {
    return immutableCopyOrNull(localVariables);
  }

  @Override
  public List<String> tags() {
    return immutableCopyOrNull(tags);
  }

  private static <T> List<T> immutableCopyOrNull(List<T> values) {
    return values == null ? null : List.copyOf(values);
  }

  public record Body(String start, String end, long numAddresses) {}

  public record ParameterResource(
      int ordinal, String name, DataTypeReference dataType, VariableStorageReference storage) {}

  public record LocalVariableResource(
      String name, DataTypeReference dataType, VariableStorageReference storage) {}
}
