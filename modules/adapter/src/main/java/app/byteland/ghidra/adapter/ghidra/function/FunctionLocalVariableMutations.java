package app.byteland.ghidra.adapter.ghidra.function;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import ghidra.app.cmd.function.SetVariableDataTypeCmd;
import ghidra.app.cmd.function.SetVariableNameCmd;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.SourceType;
import java.util.NoSuchElementException;

final class FunctionLocalVariableMutations {
  private FunctionLocalVariableMutations() {}

  static void patchLocalVariable(
      GhidraSession context,
      Function function,
      String variableName,
      String newName,
      DataTypeReference newDataType,
      FunctionMutations.ParameterDataTypeResolver dataTypeResolver) {
    patchLocalVariable(
        context, function, variableName, newName, newDataType, dataTypeResolver, fn -> null);
  }

  static void patchLocalVariable(
      GhidraSession context,
      Function function,
      String variableName,
      String newName,
      DataTypeReference newDataType,
      FunctionMutations.ParameterDataTypeResolver dataTypeResolver,
      HighFunctionReader highFunctionReader) {
    Variable variable = FunctionVariableMutationSupport.findLocalVariable(function, variableName);
    if (variable == null) {
      patchHighSymbolVariable(
          function, variableName, newName, newDataType, dataTypeResolver, highFunctionReader);
      return;
    }
    if (newName != null && !newName.isBlank()) {
      String oldName = variable.getName();
      if (!oldName.equals(newName)) {
        context.runCommand(
            new SetVariableNameCmd(variable, newName, SourceType.USER_DEFINED),
            "unable to rename variable");
        variable = FunctionVariableMutationSupport.requireLocalVariable(function, newName);
      }
    }

    if (newDataType != null) {
      DataType dt = FunctionMutationSupport.requireDataType(dataTypeResolver, newDataType);
      String oldType = String.valueOf(variable.getDataType());
      if (!oldType.equals(dt.getName())) {
        context.runCommand(
            new SetVariableDataTypeCmd(variable, dt, SourceType.USER_DEFINED),
            "failed to set variable type");
        FunctionVariableMutationSupport.requireLocalVariable(function, variable.getName());
      }
    }
  }

  private static void patchHighSymbolVariable(
      Function function,
      String variableName,
      String newName,
      DataTypeReference newDataType,
      FunctionMutations.ParameterDataTypeResolver dataTypeResolver,
      HighFunctionReader highFunctionReader) {
    HighFunction highFunction =
        (function == null || function.isExternal() || function.isThunk())
            ? null
            : highFunctionReader.read(function);
    HighSymbol highSymbol = FunctionVariableMutationSupport.findHighSymbol(highFunction, variableName);
    if (highSymbol == null) {
      throw new NoSuchElementException("local variable not found: " + variableName);
    }
    DataType resolvedType = null;
    if (newDataType != null) {
      resolvedType =
          highSymbol.isParameter()
              ? FunctionMutationSupport.requireParameterDataType(dataTypeResolver, newDataType)
              : FunctionMutationSupport.requireDataType(dataTypeResolver, newDataType);
    }
    String targetName = (newName != null && !newName.isBlank()) ? newName : null;
    DataType targetType = resolvedType;
    if (highSymbol.isParameter()
        && FunctionVariableMutationSupport.needsParameterCommit(highSymbol, highFunction)) {
      FunctionVariableMutationSupport.commitParameters(function, highFunction);
    }
    FunctionVariableMutationSupport.runHighSymbolMutation(
        () ->
            HighFunctionDBUtil.updateDBVariable(
                highSymbol, targetName, targetType, SourceType.USER_DEFINED));
  }
}
