package app.byteland.ghidra.adapter.ghidra.function;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import ghidra.app.cmd.function.SetVariableDataTypeCmd;
import ghidra.app.cmd.function.SetVariableNameCmd;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;

final class FunctionLocalVariableMutations {
  private FunctionLocalVariableMutations() {}

  static void patchLocalVariable(
      GhidraSession context,
      Function function,
      String variableName,
      String newName,
      DataTypeReference newDataType,
      FunctionMutations.ParameterDataTypeResolver dataTypeResolver) {
    Variable variable =
        FunctionVariableMutationSupport.requireLocalVariable(function, variableName);
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
}
