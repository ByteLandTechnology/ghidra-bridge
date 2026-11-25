package app.byteland.ghidra.adapter.ghidra.function;

import app.byteland.ghidra.adapter.ghidra.GhidraDataTypeReferences;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.TransactionExecutionException;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.function.VariableStorageReference;
import ghidra.app.cmd.function.DeleteVariableCmd;
import ghidra.app.cmd.function.SetVariableDataTypeCmd;
import ghidra.app.cmd.function.SetVariableNameCmd;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
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

  static void addParameter(
      GhidraSession context,
      Function function,
      int ordinal,
      String parameterName,
      DataTypeReference dataTypeInput,
      VariableStorageReference storage,
      FunctionMutations.ParameterDataTypeResolver dataTypeResolver) {
    if (parameterName == null || parameterName.isBlank()) {
      throw new IllegalArgumentException("parameter name is required");
    }
    DataType dataType =
        FunctionMutationSupport.requireParameterDataType(dataTypeResolver, dataTypeInput);
    if (storage != null) {
      addParameterWithStorage(context, function, ordinal, parameterName, dataType, storage);
      return;
    }

    ParameterImpl parameter;
    try {
      parameter =
          new ParameterImpl(
              parameterName,
              dataType,
              VariableStorage.UNASSIGNED_STORAGE,
              context.currentProgram(),
              SourceType.USER_DEFINED);
    } catch (InvalidInputException ex) {
      throw new IllegalArgumentException("unable to create parameter: " + ex.getMessage(), ex);
    }

    int insertOrdinal = resolveInsertOrdinal(function, ordinal);

    Parameter[] currentParameters = function.getParameters();
    int autoCount = 0;
    while (autoCount < currentParameters.length && currentParameters[autoCount].isAutoParameter()) {
      autoCount++;
    }
    if (insertOrdinal < autoCount) {
      throw new TransactionExecutionException(
          "unable to add parameter: Parameter may not be inserted before auto-parameter");
    }

    List<Variable> parameters = new ArrayList<>();
    FunctionUpdateType updateType;
    if (function.hasCustomVariableStorage()) {
      updateType = FunctionUpdateType.CUSTOM_STORAGE;
      for (Parameter existing : currentParameters) {
        parameters.add(existing);
      }
      parameters.add(insertOrdinal, parameter);
    } else {
      updateType = FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS;
      for (int index = autoCount; index < currentParameters.length; index++) {
        Parameter existing = currentParameters[index];
        if (!existing.isAutoParameter()) {
          parameters.add(existing);
        }
      }
      parameters.add(insertOrdinal - autoCount, parameter);
    }

    Function updated =
        FunctionMutationSupport.updateFunction(
            context,
            function,
            updateType,
            null,
            null,
            parameters,
            SourceType.USER_DEFINED,
            "unable to add parameter",
            "add parameter");
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
        parameters.add(FunctionStorageSupport.copyParameter(context.currentProgram(), parameter));
      }
    }

    applyCustomSignature(context, function, parameters, ordinal, targetStorage);
  }

  private static void addParameterWithStorage(
      GhidraSession context,
      Function function,
      int ordinal,
      String parameterName,
      DataType dataType,
      VariableStorageReference storageInput) {
    FunctionStorageSupport.ParsedStorage targetStorage =
        FunctionStorageSupport.parseExplicit(context.currentProgram(), storageInput, STORAGE_FIELD);
    int insertOrdinal = resolveInsertOrdinal(function, ordinal);

    List<Variable> parameters = new ArrayList<>();
    for (Parameter parameter : function.getParameters()) {
      parameters.add(FunctionStorageSupport.copyParameter(context.currentProgram(), parameter));
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

    applyCustomSignature(context, function, parameters, insertOrdinal, targetStorage);
  }

  private static int resolveInsertOrdinal(Function function, int ordinal) {
    int previousCount = function.getParameterCount();
    int insertOrdinal = ordinal < 0 ? previousCount : ordinal;
    if (insertOrdinal < 0 || insertOrdinal > previousCount) {
      throw new IllegalArgumentException("parameter ordinal out of range: " + insertOrdinal);
    }
    return insertOrdinal;
  }

  private static void applyCustomSignature(
      GhidraSession context,
      Function function,
      List<? extends Variable> parameters,
      int targetOrdinal,
      FunctionStorageSupport.ParsedStorage targetStorage) {
    ReturnParameterImpl returnParameter =
        FunctionStorageSupport.createReturn(
            context.currentProgram(),
            function.getReturnType(),
            function.getReturn().getVariableStorage());
    Function updated =
        FunctionMutationSupport.updateFunction(
            context,
            function,
            FunctionUpdateType.CUSTOM_STORAGE,
            null,
            returnParameter,
            parameters,
            FunctionMutationSupport.signatureSource(function),
            "unable to apply custom parameter storage",
            "custom parameter storage update");
    FunctionStorageSupport.requireSignatureApplied(updated, returnParameter, parameters);
    FunctionStorageSupport.requireValidCustomSignature(updated);
    Parameter applied = FunctionVariableMutationSupport.requireParameter(updated, targetOrdinal);
    FunctionMutationSupport.requireStorageApplied(
        STORAGE_FIELD, targetStorage.serialization(), applied.getVariableStorage());
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
