package app.byteland.ghidra.adapter.ghidra.function;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.ScriptSymbolRenamer;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.function.FunctionService.FunctionAttributePatch;
import app.byteland.ghidra.service.function.VariableStorageReference;
import ghidra.app.cmd.function.UpdateFunctionCommand;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.listing.AutoParameterType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BiConsumer;

final class FunctionMutations {
  @FunctionalInterface
  interface ParameterDataTypeResolver {
    DataType resolve(DataTypeReference input);
  }

  private FunctionMutations() {}

  static void patchFunction(
      GhidraSession context,
      Function function,
      String newName,
      String newComment,
      boolean commentPresent,
      DataTypeReference returnType,
      VariableStorageReference returnStorage,
      String callingConvention,
      FunctionAttributePatch attributes,
      ParameterDataTypeResolver dataTypeResolver) {
    FunctionAttributePatch attributePatch =
        attributes == null ? FunctionAttributePatch.empty() : attributes;
    Function updated = function;

    if (newName != null && !newName.isBlank() && !function.getName().equals(newName)) {
      Symbol symbol = context.script().getSymbolAt(function.getEntryPoint());
      if (symbol == null) {
        throw new IllegalArgumentException("function symbol not found");
      }
      ScriptSymbolRenamer.rename(context, symbol, newName);
      updated = context.script().getFunctionAt(function.getEntryPoint());
      if (updated == null) {
        throw new IllegalArgumentException("function not found after rename");
      }
    }

    if (commentPresent && !java.util.Objects.equals(updated.getComment(), newComment)) {
      if (!context.script().setPlateComment(updated.getEntryPoint(), newComment)) {
        throw new IllegalArgumentException("unable to set function comment");
      }
      updated = context.script().getFunctionAt(updated.getEntryPoint());
      if (updated == null) {
        throw new IllegalArgumentException("function not found after comment update");
      }
    }

    updated =
        patchSignature(
            context,
            updated,
            returnType,
            returnStorage,
            callingConvention,
            attributePatch.hasCustomVariableStorage(),
            dataTypeResolver);

    updated =
        patchAttribute(
            context,
            updated,
            "isInline",
            attributePatch.isInline(),
            Function::isInline,
            Function::setInline);
    updated =
        patchAttribute(
            context,
            updated,
            "hasNoReturn",
            attributePatch.hasNoReturn(),
            Function::hasNoReturn,
            Function::setNoReturn);
    updated =
        patchAttribute(
            context,
            updated,
            "hasVarArgs",
            attributePatch.hasVarArgs(),
            Function::hasVarArgs,
            Function::setVarArgs);
    patchAttribute(
        context,
        updated,
        "stackPurgeSize",
        attributePatch.stackPurgeSize(),
        Function::getStackPurgeSize,
        Function::setStackPurgeSize);
  }

  private static Function patchSignature(
      GhidraSession context,
      Function function,
      DataTypeReference returnType,
      VariableStorageReference returnStorage,
      String callingConvention,
      Boolean customStorage,
      ParameterDataTypeResolver dataTypeResolver) {
    boolean hasReturnType = returnType != null;
    boolean hasReturnStorage = returnStorage != null;
    boolean hasCallingConvention = callingConvention != null && !callingConvention.isBlank();
    if (!hasReturnType && !hasReturnStorage && !hasCallingConvention && customStorage == null) {
      return function;
    }

    if (hasReturnStorage && Boolean.FALSE.equals(customStorage)) {
      throw new IllegalArgumentException(
          "explicit storage cannot be combined with hasCustomVariableStorage=false");
    }

    String oldCallingConvention = normalizedCallingConvention(function);
    boolean oldCustomStorage = function.hasCustomVariableStorage();

    DataType targetReturnType =
        hasReturnType
            ? FunctionMutationSupport.requireDataType(dataTypeResolver, returnType)
            : hasReturnStorage
                ? function.getReturn().getFormalDataType()
                : function.getReturnType();
    FunctionStorageSupport.ParsedStorage explicitReturnStorage =
        FunctionStorageSupport.parseExplicit(
            context.currentProgram(), returnStorage, "returnStorage");
    if (explicitReturnStorage != null) {
      FunctionStorageSupport.requireCompatible(
          targetReturnType, explicitReturnStorage.storage(), "returnStorage");
    }
    boolean finalCustomStorage =
        explicitReturnStorage != null || (customStorage != null ? customStorage : oldCustomStorage);
    SourceType signatureSource = signatureSource(function);

    boolean returnTypeChanged = !function.getReturnType().isEquivalent(targetReturnType);
    boolean callingConventionChanged =
        hasCallingConvention && !oldCallingConvention.equals(callingConvention);
    Function working = function;

    if (finalCustomStorage
        && !oldCustomStorage
        && explicitReturnStorage == null
        && (returnTypeChanged || callingConventionChanged)) {
      working =
          applySignatureUpdate(
              context,
              working,
              FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
              hasCallingConvention ? callingConvention : null,
              FunctionStorageSupport.createDynamicReturn(
                  context.currentProgram(), targetReturnType),
              currentParameters(working),
              signatureSource,
              "unable to derive function storage");
      targetReturnType = working.getReturnType();
    }

    if (finalCustomStorage) {
      VariableStorage targetStorage =
          explicitReturnStorage == null
              ? working.getReturn().getVariableStorage()
              : explicitReturnStorage.storage();
      if (explicitReturnStorage == null
          && oldCustomStorage
          && returnTypeChanged
          && !FunctionStorageSupport.isVoid(targetReturnType)) {
        targetStorage =
            FunctionStorageSupport.resizeStorage(
                working, targetReturnType, targetStorage, "return storage");
      }
      ReturnParameterImpl returnParameter =
          FunctionStorageSupport.createReturn(
              context.currentProgram(), targetReturnType, targetStorage);
      List<Variable> customParameters =
          customParameterCopies(context, working, explicitReturnStorage != null);
      working =
          applySignatureUpdate(
              context,
              working,
              FunctionUpdateType.CUSTOM_STORAGE,
              hasCallingConvention ? callingConvention : null,
              returnParameter,
              customParameters,
              signatureSource,
              "unable to apply custom function storage");
      FunctionStorageSupport.requireValidCustomSignature(working);
      FunctionStorageSupport.requireSignatureApplied(working, returnParameter, customParameters);
      if (explicitReturnStorage != null) {
        FunctionMutationSupport.requireStorageApplied(
            "returnStorage",
            explicitReturnStorage.serialization(),
            working.getReturn().getVariableStorage());
      }
    } else {
      working =
          applySignatureUpdate(
              context,
              working,
              FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
              hasCallingConvention ? callingConvention : null,
              FunctionStorageSupport.createDynamicReturn(
                  context.currentProgram(), targetReturnType),
              currentParameters(working),
              signatureSource,
              "unable to update function signature");
      if (working.hasCustomVariableStorage()) {
        throw new IllegalArgumentException("unable to disable custom variable storage");
      }
    }

    return working;
  }

  private static Function applySignatureUpdate(
      GhidraSession context,
      Function function,
      FunctionUpdateType updateType,
      String callingConvention,
      Variable returnParameter,
      List<? extends Variable> parameters,
      SourceType source,
      String failureMessage) {
    context.runCommand(
        new UpdateFunctionCommand(
            function, updateType, callingConvention, returnParameter, parameters, source, false),
        failureMessage);
    return FunctionMutationSupport.refreshFunction(context, function, "signature update");
  }

  private static List<Variable> customParameterCopies(
      GhidraSession context, Function function, boolean omitReturnStoragePointer) {
    List<Variable> parameters = new ArrayList<>();
    for (Parameter parameter : function.getParameters()) {
      boolean returnStoragePointer =
          (parameter.isAutoParameter()
                  && parameter.getAutoParameterType() == AutoParameterType.RETURN_STORAGE_PTR)
              || (Function.RETURN_PTR_PARAM_NAME.equals(parameter.getName())
                  && parameter.getDataType() instanceof Pointer);
      if (omitReturnStoragePointer && returnStoragePointer) {
        continue;
      }
      parameters.add(
          FunctionStorageSupport.copyParameter(
              context.currentProgram(),
              parameter,
              parameter.getName(),
              parameter.getFormalDataType(),
              parameter.getVariableStorage()));
    }
    return parameters;
  }

  private static List<Variable> currentParameters(Function function) {
    List<Variable> parameters = new ArrayList<>();
    for (Parameter parameter : function.getParameters()) {
      parameters.add(parameter);
    }
    return parameters;
  }

  private static SourceType signatureSource(Function function) {
    SourceType source = function.getSignatureSource();
    return source == null ? SourceType.USER_DEFINED : source;
  }

  private static <T> Function patchAttribute(
      GhidraSession context,
      Function function,
      String field,
      T requestedValue,
      java.util.function.Function<Function, T> reader,
      BiConsumer<Function, T> writer) {
    if (requestedValue == null) {
      return function;
    }
    if (requestedValue.equals(reader.apply(function))) {
      return function;
    }
    writer.accept(function, requestedValue);
    Function updated =
        FunctionMutationSupport.refreshFunction(context, function, field + " update");
    T actualValue = reader.apply(updated);
    requireAppliedValue(field, requestedValue, actualValue);
    return updated;
  }

  private static void requireAppliedValue(String field, Object requestedValue, Object actualValue) {
    if (!requestedValue.equals(actualValue)) {
      throw new IllegalArgumentException(
          "unable to set " + field + " to " + requestedValue + "; actual value is " + actualValue);
    }
  }

  private static String normalizedCallingConvention(Function function) {
    String callingConvention = function.getCallingConventionName();
    return callingConvention == null ? "" : callingConvention;
  }
}
