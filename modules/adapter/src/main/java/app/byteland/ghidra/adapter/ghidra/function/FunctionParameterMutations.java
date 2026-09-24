package app.byteland.ghidra.adapter.ghidra.function;

import app.byteland.ghidra.adapter.ghidra.GhidraDataTypeReferences;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.function.VariableStorageReference;
import ghidra.app.cmd.function.AddParameterCommand;
import ghidra.app.cmd.function.DeleteVariableCmd;
import ghidra.app.cmd.function.SetVariableDataTypeCmd;
import ghidra.app.cmd.function.SetVariableNameCmd;
import ghidra.app.cmd.function.UpdateFunctionCommand;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.InvalidInputException;
import java.util.ArrayList;
import java.util.List;

final class FunctionParameterMutations {
  private static final String STORAGE_FIELD = "storage";

  private FunctionParameterMutations() {}

  static void patchParameter(
      GhidraSession context,
      Function function,
      int ordinal,
      String newName,
      DataTypeReference newDataType,
      VariableStorageReference storage,
      FunctionMutations.ParameterDataTypeResolver dataTypeResolver) {
    if (storage != null) {
      patchParameterWithStorage(
          context, function, ordinal, newName, newDataType, storage, dataTypeResolver);
      return;
    }
    Function currentFunction = function;
    Parameter parameter =
        FunctionVariableMutationSupport.requireParameter(currentFunction, ordinal);
    if (newName != null && !newName.isBlank()) {
      String oldName = parameter.getName();
      if (!oldName.equals(newName)) {
        context.runCommand(
            new SetVariableNameCmd(parameter, newName, SourceType.USER_DEFINED),
            "unable to rename parameter");
        currentFunction =
            FunctionMutationSupport.refreshFunction(context, currentFunction, "parameter rename");
        parameter = FunctionVariableMutationSupport.requireParameter(currentFunction, ordinal);
      }
    }

    if (newDataType != null) {
      DataType dt = FunctionMutationSupport.requireParameterDataType(dataTypeResolver, newDataType);
      DataTypeReference oldType =
          GhidraDataTypeReferences.toReference(parameter.getFormalDataType());
      DataTypeReference requestedType = GhidraDataTypeReferences.toReference(dt);
      if (!oldType.equals(requestedType)) {
        context.runCommand(
            new SetVariableDataTypeCmd(parameter, dt, SourceType.USER_DEFINED),
            "failed to set parameter type");
        Function refreshed =
            FunctionMutationSupport.refreshFunction(
                context, currentFunction, "parameter type update");
        FunctionVariableMutationSupport.requireParameter(refreshed, ordinal);
      }
    }
  }

  @SuppressWarnings({"deprecation", "removal"})
  static void addParameter(
      GhidraSession context,
      Function function,
      int ordinal,
      String parameterName,
      DataTypeReference dataTypeInput,
      VariableStorageReference storage,
      FunctionMutations.ParameterDataTypeResolver dataTypeResolver) {
    if (storage != null) {
      addParameterWithStorage(
          context, function, ordinal, parameterName, dataTypeInput, storage, dataTypeResolver);
      return;
    }
    if (parameterName == null || parameterName.isBlank()) {
      throw new IllegalArgumentException("parameter name is required");
    }
    if (dataTypeInput == null) {
      throw new IllegalArgumentException("dataType is required");
    }

    DataType dataType =
        FunctionMutationSupport.requireParameterDataType(dataTypeResolver, dataTypeInput);
    ParameterImpl parameter;
    try {
      parameter =
          new ParameterImpl(
              parameterName, dataType, context.currentProgram(), SourceType.USER_DEFINED);
    } catch (InvalidInputException ex) {
      throw new IllegalArgumentException("unable to create parameter: " + ex.getMessage(), ex);
    }

    int previousCount = function.getParameterCount();
    int insertOrdinal = ordinal < 0 ? previousCount : ordinal;
    if (insertOrdinal < 0 || insertOrdinal > previousCount) {
      throw new IllegalArgumentException("parameter ordinal out of range: " + insertOrdinal);
    }

    context.runCommand(
        new AddParameterCommand(function, parameter, insertOrdinal, SourceType.USER_DEFINED),
        "unable to add parameter");

    Function updated = FunctionMutationSupport.refreshFunction(context, function, "add parameter");
    FunctionVariableMutationSupport.requireParameter(updated, insertOrdinal);
  }

  private static void patchParameterWithStorage(
      GhidraSession context,
      Function function,
      int ordinal,
      String newName,
      DataTypeReference newDataType,
      VariableStorageReference storageInput,
      FunctionMutations.ParameterDataTypeResolver dataTypeResolver) {
    Parameter original = FunctionVariableMutationSupport.requireParameter(function, ordinal);
    String oldName = original.getName();
    String targetName = newName == null || newName.isBlank() ? oldName : newName;
    DataType targetDataType =
        newDataType == null
            ? original.getFormalDataType()
            : FunctionMutationSupport.requireParameterDataType(dataTypeResolver, newDataType);
    FunctionStorageSupport.ParsedStorage targetStorage =
        FunctionStorageSupport.parseExplicit(context.currentProgram(), storageInput, STORAGE_FIELD);

    List<Variable> parameters = new ArrayList<>();
    Parameter[] currentParameters = function.getParameters();
    for (int index = 0; index < currentParameters.length; index++) {
      Parameter parameter = currentParameters[index];
      if (index == ordinal) {
        ParameterImpl replacement =
            FunctionStorageSupport.createParameter(
                context.currentProgram(),
                targetName,
                parameter.getOrdinal(),
                targetDataType,
                targetStorage.storage(),
                SourceType.USER_DEFINED,
                "parameter " + ordinal);
        replacement.setComment(parameter.getComment());
        parameters.add(replacement);
      } else {
        parameters.add(
            FunctionStorageSupport.copyParameter(
                context.currentProgram(),
                parameter,
                parameter.getName(),
                parameter.getFormalDataType(),
                parameter.getVariableStorage()));
      }
    }

    Function updated = applyCustomSignature(context, function, parameters);
    FunctionStorageSupport.requireValidCustomSignature(updated);
    Parameter actual = FunctionVariableMutationSupport.requireParameter(updated, ordinal);
    FunctionMutationSupport.requireStorageApplied(
        STORAGE_FIELD, targetStorage.serialization(), actual.getVariableStorage());
  }

  private static void addParameterWithStorage(
      GhidraSession context,
      Function function,
      int ordinal,
      String parameterName,
      DataTypeReference dataTypeInput,
      VariableStorageReference storageInput,
      FunctionMutations.ParameterDataTypeResolver dataTypeResolver) {
    if (parameterName == null || parameterName.isBlank()) {
      throw new IllegalArgumentException("parameter name is required");
    }
    if (dataTypeInput == null) {
      throw new IllegalArgumentException("dataType is required");
    }

    DataType dataType =
        FunctionMutationSupport.requireParameterDataType(dataTypeResolver, dataTypeInput);
    FunctionStorageSupport.ParsedStorage targetStorage =
        FunctionStorageSupport.parseExplicit(context.currentProgram(), storageInput, STORAGE_FIELD);
    int previousCount = function.getParameterCount();
    int insertOrdinal = ordinal < 0 ? previousCount : ordinal;
    if (insertOrdinal < 0 || insertOrdinal > previousCount) {
      throw new IllegalArgumentException("parameter ordinal out of range: " + insertOrdinal);
    }

    List<Variable> parameters = new ArrayList<>();
    for (Parameter parameter : function.getParameters()) {
      parameters.add(
          FunctionStorageSupport.copyParameter(
              context.currentProgram(),
              parameter,
              parameter.getName(),
              parameter.getFormalDataType(),
              parameter.getVariableStorage()));
    }
    parameters.add(
        insertOrdinal,
        FunctionStorageSupport.createParameter(
            context.currentProgram(),
            parameterName,
            insertOrdinal,
            dataType,
            targetStorage.storage(),
            SourceType.USER_DEFINED,
            "parameter " + insertOrdinal));

    Function updated = applyCustomSignature(context, function, parameters);
    FunctionStorageSupport.requireValidCustomSignature(updated);
    Parameter added = FunctionVariableMutationSupport.requireParameter(updated, insertOrdinal);
    FunctionMutationSupport.requireStorageApplied(
        STORAGE_FIELD, targetStorage.serialization(), added.getVariableStorage());
  }

  private static Function applyCustomSignature(
      GhidraSession context, Function function, List<? extends Variable> parameters) {
    ReturnParameterImpl returnParameter =
        FunctionStorageSupport.createReturn(
            context.currentProgram(),
            function.getReturnType(),
            function.getReturn().getVariableStorage());
    SourceType source = function.getSignatureSource();
    if (source == null) {
      source = SourceType.USER_DEFINED;
    }
    context.runCommand(
        new UpdateFunctionCommand(
            function,
            FunctionUpdateType.CUSTOM_STORAGE,
            null,
            returnParameter,
            parameters,
            source,
            false),
        "unable to apply custom parameter storage");
    Function updated =
        FunctionMutationSupport.refreshFunction(
            context, function, "custom parameter storage update");
    FunctionStorageSupport.requireSignatureApplied(updated, returnParameter, parameters);
    return updated;
  }

  static void removeParameter(GhidraSession context, Function function, int ordinal) {
    Parameter parameter = FunctionVariableMutationSupport.requireParameter(function, ordinal);
    if (parameter.isAutoParameter()) {
      throw new IllegalArgumentException("cannot remove auto parameter at ordinal: " + ordinal);
    }

    context.runCommand(new DeleteVariableCmd(parameter), "unable to remove parameter");

    FunctionMutationSupport.refreshFunction(context, function, "remove parameter");
  }
}
