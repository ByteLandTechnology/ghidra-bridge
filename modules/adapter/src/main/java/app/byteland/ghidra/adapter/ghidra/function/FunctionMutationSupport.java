package app.byteland.ghidra.adapter.ghidra.function;

import app.byteland.ghidra.adapter.ghidra.GhidraDataTypeReferences;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import ghidra.app.cmd.function.UpdateFunctionCommand;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.SourceType;
import java.util.List;

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

  static SourceType signatureSource(Function function) {
    SourceType source = function.getSignatureSource();
    return source == null ? SourceType.USER_DEFINED : source;
  }

  static Function updateFunction(
      GhidraSession context,
      Function function,
      FunctionUpdateType updateType,
      String callingConvention,
      Variable returnVar,
      List<? extends Variable> parameters,
      SourceType source,
      String failureMessage,
      String operation) {
    context.runCommand(
        new UpdateFunctionCommand(
            function, updateType, callingConvention, returnVar, parameters, source, false),
        failureMessage);
    return refreshFunction(context, function, operation);
  }

  static Function refreshFunction(GhidraSession context, Function function, String operation) {
    Function updated = context.flatApi().getFunctionAt(function.getEntryPoint());
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
