package app.byteland.ghidra.adapter.ghidra.function;

import app.byteland.ghidra.adapter.ghidra.GhidraCParserSupport;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.ScriptSymbolRenamer;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.function.FunctionService.FunctionAttributePatch;
import app.byteland.ghidra.service.function.FunctionService.ParameterPatch;
import app.byteland.ghidra.service.function.VariableStorageReference;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.function.FunctionRenameOption;
import ghidra.app.cmd.function.UpdateFunctionCommand;
import ghidra.program.model.data.AbstractFloatDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.listing.AutoParameterType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.exception.InvalidInputException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
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
      List<ParameterPatch> parameters,
      String signature,
      ParameterDataTypeResolver dataTypeResolver) {
    if (signature != null
        && (parameters != null || returnType != null || callingConvention != null)) {
      throw new IllegalArgumentException(
          "signature cannot be combined with parameters, returnType, or callingConvention");
    }
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

    if (commentPresent && !Objects.equals(updated.getComment(), newComment)) {
      if (!context.script().setPlateComment(updated.getEntryPoint(), newComment)) {
        throw new IllegalArgumentException("unable to set function comment");
      }
      updated = context.script().getFunctionAt(updated.getEntryPoint());
      if (updated == null) {
        throw new IllegalArgumentException("function not found after comment update");
      }
    }

    if (signature != null) {
      updated =
          applyTextSignature(
              context,
              updated,
              signature,
              newName != null && !newName.isBlank(),
              returnStorage,
              attributePatch.hasCustomVariableStorage());
    } else if (parameters != null) {
      updated =
          patchSignatureWithParameters(
              context,
              updated,
              returnType,
              returnStorage,
              callingConvention,
              attributePatch.hasCustomVariableStorage(),
              parameters,
              dataTypeResolver);
    } else {
      updated =
          patchSignature(
              context,
              updated,
              returnType,
              returnStorage,
              callingConvention,
              attributePatch.hasCustomVariableStorage(),
              dataTypeResolver);
    }

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

  private static Function applyTextSignature(
      GhidraSession context,
      Function function,
      String signatureText,
      boolean explicitNameAlreadySet,
      VariableStorageReference returnStorage,
      Boolean customStorage) {
    if (returnStorage != null && Boolean.FALSE.equals(customStorage)) {
      throw new IllegalArgumentException(
          "explicit storage cannot be combined with hasCustomVariableStorage=false");
    }
    Program program = context.currentProgram();
    boolean oldCustomStorage = function.hasCustomVariableStorage();
    VariableStorage oldReturnStorage = function.getReturn().getVariableStorage();
    List<ParameterSnapshot> oldParameters = snapshotParameters(function);

    GhidraCParserSupport.ParsedFunctionSignature parsed =
        GhidraCParserSupport.parseFunctionSignature(
            program.getDataTypeManager(), function, signatureText);
    FunctionRenameOption renameOption =
        explicitNameAlreadySet || parsed.definition().getName().equals(function.getName())
            ? FunctionRenameOption.NO_CHANGE
            : FunctionRenameOption.RENAME;
    boolean preserveCallingConvention = !parsed.explicitCallingConvention();

    context.runCommand(
        new ApplyFunctionSignatureCmd(
            function.getEntryPoint(),
            parsed.definition(),
            SourceType.USER_DEFINED,
            preserveCallingConvention,
            false,
            DataTypeConflictHandler.DEFAULT_HANDLER,
            renameOption),
        "unable to apply C function signature");
    Function updated =
        FunctionMutationSupport.refreshFunction(context, function, "C signature update");

    FunctionStorageSupport.ParsedStorage explicitReturnStorage =
        FunctionStorageSupport.parseExplicit(program, returnStorage, "returnStorage");
    if (explicitReturnStorage != null) {
      FunctionStorageSupport.requireCompatible(
          updated.getReturnType(), explicitReturnStorage.storage(), "returnStorage");
    }

    boolean wantCustom =
        explicitReturnStorage != null
            || Boolean.TRUE.equals(customStorage)
            || (customStorage == null
                && oldCustomStorage
                && canPreserveCustomSignatureStorage(updated, oldReturnStorage, oldParameters));
    if (!wantCustom) {
      return updated;
    }

    VariableStorage targetReturnStorage;
    if (explicitReturnStorage != null) {
      targetReturnStorage = explicitReturnStorage.storage();
    } else if (FunctionStorageSupport.isVoid(updated.getReturnType())) {
      targetReturnStorage = VariableStorage.VOID_STORAGE;
    } else if (oldCustomStorage && isStorageCompatible(updated.getReturnType(), oldReturnStorage)) {
      targetReturnStorage = oldReturnStorage;
    } else {
      targetReturnStorage = updated.getReturn().getVariableStorage();
    }

    ReturnParameterImpl returnParam =
        FunctionStorageSupport.createReturn(program, updated.getReturnType(), targetReturnStorage);
    Parameter[] appliedParams = updated.getParameters();
    Set<Integer> claimedOldIndices = new HashSet<>();
    List<Variable> customParams = new ArrayList<>(appliedParams.length);
    for (int index = 0; index < appliedParams.length; index++) {
      Parameter current = appliedParams[index];
      DataType paramType = current.getFormalDataType();
      ParameterSnapshot matchedOld =
          oldCustomStorage
              ? findMatchingOldParameter(
                  oldParameters, claimedOldIndices, current.getName(), index, paramType)
              : null;
      VariableStorage chosen =
          matchedOld != null ? matchedOld.storage() : current.getVariableStorage();
      ParameterImpl rebuilt =
          FunctionStorageSupport.createParameter(
              program,
              current.getName(),
              index,
              paramType,
              chosen,
              SourceType.USER_DEFINED,
              "parameter " + index);
      if (matchedOld != null && matchedOld.comment() != null) {
        rebuilt.setComment(matchedOld.comment());
      }
      customParams.add(rebuilt);
    }

    updated =
        applySignatureUpdate(
            context,
            updated,
            FunctionUpdateType.CUSTOM_STORAGE,
            null,
            returnParam,
            customParams,
            SourceType.USER_DEFINED,
            "unable to preserve custom storage after C signature update");
    FunctionStorageSupport.requireValidCustomSignature(updated);
    FunctionStorageSupport.requireSignatureApplied(updated, returnParam, customParams);
    if (explicitReturnStorage != null) {
      FunctionMutationSupport.requireStorageApplied(
          "returnStorage",
          explicitReturnStorage.serialization(),
          updated.getReturn().getVariableStorage());
    }
    return updated;
  }

  private static Function patchSignatureWithParameters(
      GhidraSession context,
      Function function,
      DataTypeReference returnType,
      VariableStorageReference returnStorage,
      String callingConvention,
      Boolean customStorage,
      List<ParameterPatch> parameterPatches,
      ParameterDataTypeResolver dataTypeResolver) {
    Program program = context.currentProgram();
    boolean hasReturnType = returnType != null;
    boolean hasReturnStorage = returnStorage != null;
    boolean hasCallingConvention = callingConvention != null && !callingConvention.isBlank();
    boolean anyExplicitParamStorage =
        parameterPatches.stream().anyMatch(item -> item.storage() != null);

    if ((hasReturnStorage || anyExplicitParamStorage) && Boolean.FALSE.equals(customStorage)) {
      throw new IllegalArgumentException(
          "explicit storage cannot be combined with hasCustomVariableStorage=false");
    }

    boolean oldCustomStorage = function.hasCustomVariableStorage();
    VariableStorage oldReturnStorage = function.getReturn().getVariableStorage();
    List<ParameterSnapshot> oldParameters = snapshotParameters(function);
    SourceType signatureSource = signatureSource(function);

    DataType targetReturnType =
        hasReturnType
            ? FunctionMutationSupport.requireDataType(dataTypeResolver, returnType)
            : hasReturnStorage
                ? function.getReturn().getFormalDataType()
                : function.getReturnType();
    FunctionStorageSupport.ParsedStorage explicitReturnStorage =
        FunctionStorageSupport.parseExplicit(program, returnStorage, "returnStorage");
    if (explicitReturnStorage != null) {
      FunctionStorageSupport.requireCompatible(
          targetReturnType, explicitReturnStorage.storage(), "returnStorage");
    }

    List<ResolvedParameterInput> resolvedInputs = new ArrayList<>(parameterPatches.size());
    for (int index = 0; index < parameterPatches.size(); index++) {
      ParameterPatch patchItem = parameterPatches.get(index);
      DataType paramType =
          FunctionMutationSupport.requireParameterDataType(dataTypeResolver, patchItem.dataType());
      FunctionStorageSupport.ParsedStorage explicitStorage =
          FunctionStorageSupport.parseExplicit(
              program, patchItem.storage(), "parameters[" + index + "].storage");
      if (explicitStorage != null) {
        FunctionStorageSupport.requireCompatible(
            paramType, explicitStorage.storage(), "parameters[" + index + "].storage");
      }
      resolvedInputs.add(new ResolvedParameterInput(patchItem.name(), paramType, explicitStorage));
    }

    boolean finalCustomStorage =
        explicitReturnStorage != null
            || anyExplicitParamStorage
            || (customStorage != null ? customStorage : oldCustomStorage);

    List<Variable> dynamicParameters = buildDynamicParameterList(program, resolvedInputs, oldParameters);

    if (!finalCustomStorage) {
      Function updated =
          applySignatureUpdate(
              context,
              function,
              FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
              hasCallingConvention ? callingConvention : null,
              FunctionStorageSupport.createDynamicReturn(program, targetReturnType),
              dynamicParameters,
              signatureSource,
              "unable to update function parameters");
      if (updated.hasCustomVariableStorage()) {
        throw new IllegalArgumentException("unable to disable custom variable storage");
      }
      return updated;
    }

    // Match compatible prior custom storage for parameters without explicit storage.
    Set<Integer> claimedOld = new HashSet<>();
    List<VariableStorage> chosenStorages = new ArrayList<>(resolvedInputs.size());
    boolean needsDynamicDerivation = false;
    for (int index = 0; index < resolvedInputs.size(); index++) {
      ResolvedParameterInput input = resolvedInputs.get(index);
      if (input.explicitStorage() != null) {
        chosenStorages.add(input.explicitStorage().storage());
      } else if (oldCustomStorage) {
        ParameterSnapshot matched =
            findMatchingOldParameter(
                oldParameters, claimedOld, input.name(), index, input.dataType());
        if (matched != null) {
          chosenStorages.add(matched.storage());
        } else {
          chosenStorages.add(null);
          needsDynamicDerivation = true;
        }
      } else {
        chosenStorages.add(null);
        needsDynamicDerivation = true;
      }
    }

    boolean returnNeedsDerivation =
        explicitReturnStorage == null
            && !FunctionStorageSupport.isVoid(targetReturnType)
            && (!oldCustomStorage || !isStorageCompatible(targetReturnType, oldReturnStorage));

    Function working = function;
    if (needsDynamicDerivation || returnNeedsDerivation) {
      working =
          applySignatureUpdate(
              context,
              working,
              FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
              hasCallingConvention ? callingConvention : null,
              FunctionStorageSupport.createDynamicReturn(program, targetReturnType),
              dynamicParameters,
              signatureSource,
              "unable to derive function parameter storage");
    }

    VariableStorage targetReturnStorage;
    if (explicitReturnStorage != null) {
      targetReturnStorage = explicitReturnStorage.storage();
    } else if (FunctionStorageSupport.isVoid(targetReturnType)) {
      targetReturnStorage = VariableStorage.VOID_STORAGE;
    } else if (oldCustomStorage && isStorageCompatible(targetReturnType, oldReturnStorage)) {
      targetReturnStorage = oldReturnStorage;
    } else if (oldCustomStorage && !returnNeedsDerivation) {
      targetReturnStorage =
          FunctionStorageSupport.resizeStorage(
              working, targetReturnType, oldReturnStorage, "return storage");
    } else {
      targetReturnStorage = working.getReturn().getVariableStorage();
    }

    ReturnParameterImpl returnParameter =
        FunctionStorageSupport.createReturn(program, targetReturnType, targetReturnStorage);
    Parameter[] derivedParams = working.getParameters();
    List<Variable> customParameters = new ArrayList<>(resolvedInputs.size());
    for (int index = 0; index < resolvedInputs.size(); index++) {
      ResolvedParameterInput input = resolvedInputs.get(index);
      VariableStorage storage = chosenStorages.get(index);
      if (storage == null) {
        if (index >= derivedParams.length) {
          throw new IllegalArgumentException(
              "derived parameter storage missing at ordinal " + index);
        }
        storage = derivedParams[index].getVariableStorage();
      }
      ParameterImpl customParam =
          FunctionStorageSupport.createParameter(
              program,
              input.name(),
              index,
              input.dataType(),
              storage,
              SourceType.USER_DEFINED,
              "parameter " + index);
      customParameters.add(customParam);
    }

    working =
        applySignatureUpdate(
            context,
            working,
            FunctionUpdateType.CUSTOM_STORAGE,
            hasCallingConvention ? callingConvention : null,
            returnParameter,
            customParameters,
            signatureSource,
            "unable to apply custom function parameters");
    FunctionStorageSupport.requireValidCustomSignature(working);
    FunctionStorageSupport.requireSignatureApplied(working, returnParameter, customParameters);
    if (explicitReturnStorage != null) {
      FunctionMutationSupport.requireStorageApplied(
          "returnStorage",
          explicitReturnStorage.serialization(),
          working.getReturn().getVariableStorage());
    }
    for (int index = 0; index < resolvedInputs.size(); index++) {
      FunctionStorageSupport.ParsedStorage explicit = resolvedInputs.get(index).explicitStorage();
      if (explicit != null) {
        FunctionMutationSupport.requireStorageApplied(
            "parameters[" + index + "].storage",
            explicit.serialization(),
            working.getParameter(index).getVariableStorage());
      }
    }
    return working;
  }

  private static List<Variable> buildDynamicParameterList(
      Program program,
      List<ResolvedParameterInput> inputs,
      List<ParameterSnapshot> oldParameters) {
    List<Variable> result = new ArrayList<>(inputs.size());
    Set<Integer> claimedComments = new HashSet<>();
    for (int index = 0; index < inputs.size(); index++) {
      ResolvedParameterInput input = inputs.get(index);
      try {
        ParameterImpl parameter =
            new ParameterImpl(input.name(), input.dataType(), program, SourceType.USER_DEFINED);
        String preservedComment = findPreservedComment(oldParameters, claimedComments, input.name());
        if (preservedComment != null) {
          parameter.setComment(preservedComment);
        }
        result.add(parameter);
      } catch (InvalidInputException error) {
        throw new IllegalArgumentException(
            "unable to construct parameter " + index + ": " + error.getMessage(), error);
      }
    }
    return result;
  }

  private static boolean canPreserveCustomSignatureStorage(
      Function updated,
      VariableStorage oldReturnStorage,
      List<ParameterSnapshot> oldParameters) {
    if (!FunctionStorageSupport.isVoid(updated.getReturnType())
        && !isStorageCompatible(updated.getReturnType(), oldReturnStorage)) {
      return false;
    }
    Parameter[] current = updated.getParameters();
    Set<Integer> claimed = new HashSet<>();
    for (int i = 0; i < current.length; i++) {
      ParameterSnapshot matched =
          findMatchingOldParameter(
              oldParameters, claimed, current[i].getName(), i, current[i].getFormalDataType());
      if (matched == null) {
        return false;
      }
    }
    return true;
  }

  private static ParameterSnapshot findMatchingOldParameter(
      List<ParameterSnapshot> oldParameters,
      Set<Integer> claimedIndices,
      String candidateName,
      int candidateOrdinal,
      DataType targetType) {
    if (candidateName != null
        && !candidateName.isBlank()
        && !SymbolUtilities.isDefaultParameterName(candidateName)) {
      int uniqueMatch = -1;
      int nameMatches = 0;
      for (int i = 0; i < oldParameters.size(); i++) {
        if (claimedIndices.contains(i)) continue;
        if (candidateName.equals(oldParameters.get(i).name())) {
          uniqueMatch = i;
          nameMatches++;
        }
      }
      if (nameMatches == 1) {
        ParameterSnapshot snapshot = oldParameters.get(uniqueMatch);
        if (isStorageCompatible(targetType, snapshot.storage())) {
          claimedIndices.add(uniqueMatch);
          return snapshot;
        }
        return null;
      }
    }
    if (candidateOrdinal >= 0
        && candidateOrdinal < oldParameters.size()
        && !claimedIndices.contains(candidateOrdinal)) {
      ParameterSnapshot atSameOrdinal = oldParameters.get(candidateOrdinal);
      boolean nameAllowsOrdinalFallback =
          candidateName == null
              || SymbolUtilities.isDefaultParameterName(candidateName)
              || Objects.equals(candidateName, atSameOrdinal.name())
              || oldParameters.stream().noneMatch(p -> Objects.equals(candidateName, p.name()));
      if (nameAllowsOrdinalFallback && isStorageCompatible(targetType, atSameOrdinal.storage())) {
        claimedIndices.add(candidateOrdinal);
        return atSameOrdinal;
      }
    }
    return null;
  }

  private static String findPreservedComment(
      List<ParameterSnapshot> oldParameters, Set<Integer> claimed, String name) {
    if (name == null || name.isBlank() || SymbolUtilities.isDefaultParameterName(name)) {
      return null;
    }
    for (int i = 0; i < oldParameters.size(); i++) {
      if (claimed.contains(i)) continue;
      if (name.equals(oldParameters.get(i).name())) {
        claimed.add(i);
        return oldParameters.get(i).comment();
      }
    }
    return null;
  }

  private static boolean isStorageCompatible(DataType dataType, VariableStorage storage) {
    if (FunctionStorageSupport.isVoid(dataType) || storage == null) {
      return false;
    }
    if (!storage.isValid()
        || storage.isBadStorage()
        || storage.isUnassignedStorage()
        || storage.isVoidStorage()
        || storage.isAutoStorage()
        || storage.isForcedIndirect()) {
      return false;
    }
    int length = dataType.getLength();
    if (length <= 0) {
      return false;
    }
    return storage.size() == length || dataType instanceof AbstractFloatDataType;
  }

  private static List<ParameterSnapshot> snapshotParameters(Function function) {
    Parameter[] parameters = function.getParameters();
    List<ParameterSnapshot> snapshots = new ArrayList<>(parameters.length);
    for (Parameter parameter : parameters) {
      snapshots.add(
          new ParameterSnapshot(
              parameter.getName(),
              parameter.getFormalDataType(),
              parameter.getVariableStorage(),
              parameter.getComment()));
    }
    return snapshots;
  }

  private record ParameterSnapshot(
      String name, DataType dataType, VariableStorage storage, String comment) {}

  private record ResolvedParameterInput(
      String name,
      DataType dataType,
      FunctionStorageSupport.ParsedStorage explicitStorage) {}

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
