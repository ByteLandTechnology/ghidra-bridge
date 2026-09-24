package app.byteland.ghidra.adapter.ghidra.function;

import app.byteland.ghidra.adapter.ghidra.GhidraDataTypeReferences;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.VariableStorage;

final class FunctionMutationSupport {
  private FunctionMutationSupport() {}

  static DataType requireDataType(
      FunctionMutations.ParameterDataTypeResolver dataTypeResolver, DataTypeReference input) {
    DataType dataType = dataTypeResolver.resolve(input);
    if (dataType == null) {
      throw new IllegalArgumentException("unknown data type: " + input);
    }
    return dataType;
  }

  static DataType requireParameterDataType(
      FunctionMutations.ParameterDataTypeResolver dataTypeResolver, DataTypeReference input) {
    if (input == null) {
      throw new IllegalArgumentException("dataType is required");
    }
    DataType dataType = requireDataType(dataTypeResolver, input);
    if (GhidraDataTypeReferences.isBareFunctionDefinition(dataType)) {
      throw new IllegalArgumentException(
          "function definition parameter types must use kind=pointer: " + dataType.getPathName());
    }
    return dataType;
  }

  static Function refreshFunction(GhidraSession context, Function function, String operation) {
    Function updated = context.script().getFunctionAt(function.getEntryPoint());
    if (updated == null) {
      throw new IllegalArgumentException("function not found after " + operation);
    }
    return updated;
  }

  static void requireStorageApplied(
      String field, String expectedSerialization, VariableStorage actualStorage) {
    String actualSerialization = actualStorage.getSerializationString();
    if (!expectedSerialization.equals(actualSerialization)) {
      throw new IllegalArgumentException(
          field
              + " was not applied exactly; expected "
              + expectedSerialization
              + " but actual storage is "
              + actualSerialization);
    }
  }
}
