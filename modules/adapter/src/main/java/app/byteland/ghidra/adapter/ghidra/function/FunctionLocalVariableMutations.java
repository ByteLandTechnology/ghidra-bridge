package app.byteland.ghidra.adapter.ghidra.function;

import app.byteland.ghidra.adapter.ghidra.GhidraDataTypeReferences;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.decompilation.DecompilerPool;
import app.byteland.ghidra.adapter.ghidra.function.FunctionStorageSupport.ParsedStorage;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.function.VariableStorageReference;
import ghidra.app.cmd.function.SetVariableDataTypeCmd;
import ghidra.app.cmd.function.SetVariableNameCmd;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

final class FunctionLocalVariableMutations {
  private FunctionLocalVariableMutations() {}

  static void patchLocalVariable(
      GhidraSession context,
      DecompilerPool decompilerPool,
      Function function,
      String variableName,
      VariableStorageReference selectorStorage,
      String newName,
      DataTypeReference newDataType,
      FunctionMutations.ParameterDataTypeResolver dataTypeResolver) {
    ParsedStorage parsedStorage =
        FunctionStorageSupport.parseLocalSelector(
            function.getProgram(), selectorStorage, "selector.storage");
    Variable variable =
        FunctionVariableMutationSupport.findCommittedLocalVariable(
            function, variableName, parsedStorage);
    if (variable != null) {
      patchCommittedLocalVariable(
          context, function, variable, newName, newDataType, dataTypeResolver);
      return;
    }

    HighFunction highFunction = decompilerPool.decompileHighFunction(function);
    HighSymbol highSymbol =
        FunctionVariableMutationSupport.requireHighLocalSymbol(
            highFunction, variableName, parsedStorage);
    String targetName =
        newName != null && !newName.isBlank() ? newName : highSymbol.getName();
    DataType targetDataType =
        newDataType == null
            ? null
            : FunctionMutationSupport.requireDataType(dataTypeResolver, newDataType);
    try {
      HighFunctionDBUtil.updateDBVariable(
          highSymbol, targetName, targetDataType, SourceType.USER_DEFINED);
    } catch (DuplicateNameException | InvalidInputException ex) {
      throw new IllegalArgumentException(
          "unable to update local variable: " + ex.getMessage(), ex);
    }
    Variable committed = FunctionVariableMutationSupport.requireLocalVariable(function, targetName);
    if (targetDataType != null) {
      DataTypeReference currentType = GhidraDataTypeReferences.toReference(committed.getDataType());
      DataTypeReference expectedType = GhidraDataTypeReferences.toReference(targetDataType);
      if (!currentType.equals(expectedType)) {
        context.runCommand(
            new SetVariableDataTypeCmd(committed, targetDataType, SourceType.USER_DEFINED),
            "failed to set variable type");
        FunctionVariableMutationSupport.requireLocalVariable(function, targetName);
      }
    }
  }

  private static void patchCommittedLocalVariable(
      GhidraSession context,
      Function function,
      Variable variable,
      String newName,
      DataTypeReference newDataType,
      FunctionMutations.ParameterDataTypeResolver dataTypeResolver) {
    Variable current = variable;
    if (newName != null && !newName.isBlank()) {
      String oldName = current.getName();
      if (!oldName.equals(newName)) {
        context.runCommand(
            new SetVariableNameCmd(current, newName, SourceType.USER_DEFINED),
            "unable to rename variable");
        current = FunctionVariableMutationSupport.requireLocalVariable(function, newName);
      }
    }

    if (newDataType != null) {
      DataType dt = FunctionMutationSupport.requireDataType(dataTypeResolver, newDataType);
      DataTypeReference oldType = GhidraDataTypeReferences.toReference(current.getDataType());
      DataTypeReference nextType = GhidraDataTypeReferences.toReference(dt);
      if (!oldType.equals(nextType)) {
        context.runCommand(
            new SetVariableDataTypeCmd(current, dt, SourceType.USER_DEFINED),
            "failed to set variable type");
        FunctionVariableMutationSupport.requireLocalVariable(function, current.getName());
      }
    }
  }
}
