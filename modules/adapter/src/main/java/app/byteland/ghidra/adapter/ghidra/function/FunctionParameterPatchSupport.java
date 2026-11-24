package app.byteland.ghidra.adapter.ghidra.function;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.datatype.DataTypeMutationValidationException;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.function.FunctionService.ParameterPatch;
import app.byteland.ghidra.service.function.VariableStorageReference;
import ghidra.app.cmd.function.UpdateFunctionCommand;
import ghidra.program.model.data.AbstractFloatDataType;
import ghidra.program.model.data.DataType;
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
import ghidra.program.model.listing.VariableUtilities;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.exception.InvalidInputException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Applies atomic parameter list updates and preserves compatible custom variable storage across
 * {@code function.patch} operations.
 */
final class FunctionParameterPatchSupport {
  private static final String CUSTOM_STORAGE_TARGET = "/patch/has_custom_variable_storage";
  private static final String RETURN_TYPE_TARGET = "/patch/return_type";
  private static final String RETURN_STORAGE_TARGET = "/patch/return_storage";

  private FunctionParameterPatchSupport() {}

  record ParameterSnapshot(
      String name,
      DataType dataType,
      VariableStorage storage,
      String comment,
      boolean autoParameter) {}

  static List<ParameterSnapshot> snapshotParameters(Function function) {
    Parameter[] parameters = function.getParameters();
    List<ParameterSnapshot> snapshots = new ArrayList<>(parameters.length);
    for (Parameter parameter : parameters) {
      snapshots.add(
          new ParameterSnapshot(
              parameter.getName(),
              parameter.getFormalDataType(),
              parameter.getVariableStorage(),
              parameter.getComment(),
              parameter.isAutoParameter()));
    }
    return snapshots;
  }

  static Function patchParameters(
      GhidraSession context,
      Function function,
      DataTypeReference returnType,
      VariableStorageReference returnStorage,
      String callingConvention,
      Boolean customStorage,
      List<ParameterPatch> parameterPatches,
      FunctionMutations.ParameterDataTypeResolver dataTypeResolver) {
    Program program = context.currentProgram();
    boolean hasReturnType = returnType != null;
    boolean hasReturnStorage = returnStorage != null;
    boolean hasCallingConvention = callingConvention != null && !callingConvention.isBlank();
    boolean anyExplicitParamStorage =
        parameterPatches.stream().anyMatch(item -> item != null && item.storage() != null);

    if ((hasReturnStorage || anyExplicitParamStorage) && Boolean.FALSE.equals(customStorage)) {
      throw new DataTypeMutationValidationException(
          CUSTOM_STORAGE_TARGET,
          "explicit storage cannot be combined with hasCustomVariableStorage=false");
    }

    boolean oldCustomStorage = function.hasCustomVariableStorage();
    VariableStorage oldReturnStorage = function.getReturn().getVariableStorage();
    List<ParameterSnapshot> oldParameters = snapshotParameters(function);

    DataType targetReturnType =
        hasReturnType
            ? resolveReturnDataType(dataTypeResolver, returnType)
            : hasReturnStorage
                ? function.getReturn().getFormalDataType()
                : function.getReturnType();
    FunctionStorageSupport.ParsedStorage explicitReturnStorage =
        parseAndValidateStorage(
            program, targetReturnType, returnStorage, "returnStorage", RETURN_STORAGE_TARGET);

    List<ResolvedParameterInput> resolvedInputs =
        resolveParameterInputs(program, parameterPatches, dataTypeResolver);
    boolean finalCustomStorage =
        explicitReturnStorage != null
            || anyExplicitParamStorage
            || (customStorage != null ? customStorage : oldCustomStorage);

    List<Variable> dynamicParameters =
        buildDynamicParameterList(program, resolvedInputs, oldParameters);
    if (!finalCustomStorage) {
      Function updated =
          applySignatureUpdate(
              context,
              function,
              FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
              hasCallingConvention ? callingConvention : null,
              FunctionStorageSupport.createDynamicReturn(program, targetReturnType),
              dynamicParameters,
              "unable to update function parameters");
      if (updated.hasCustomVariableStorage()) {
        throw new IllegalArgumentException("unable to disable custom variable storage");
      }
      return updated;
    }

    MatchedParameterPlan matchedPlan =
        matchCustomParameterStorages(function, resolvedInputs, oldParameters, oldCustomStorage);
    boolean returnNeedsDerivation =
        explicitReturnStorage == null
            && !FunctionStorageSupport.isVoid(targetReturnType)
            && (!oldCustomStorage
                || adaptCompatibleStorage(function, targetReturnType, oldReturnStorage) == null);

    Function working = function;
    if (matchedPlan.needsDynamicDerivation() || returnNeedsDerivation) {
      working =
          applySignatureUpdate(
              context,
              working,
              FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
              hasCallingConvention ? callingConvention : null,
              FunctionStorageSupport.createDynamicReturn(program, targetReturnType),
              dynamicParameters,
              "unable to derive function parameter storage");
    }

    VariableStorage targetReturnStorage =
        resolveTargetReturnStorage(
            working, targetReturnType, explicitReturnStorage, oldCustomStorage, oldReturnStorage);
    ReturnParameterImpl returnParameter =
        FunctionStorageSupport.createReturn(program, targetReturnType, targetReturnStorage);

    Parameter[] derivedParams = working.getParameters();
    int autoOffset = countLeadingAutoParameters(derivedParams);
    List<Variable> customParameters = new ArrayList<>(resolvedInputs.size());
    for (int index = 0; index < resolvedInputs.size(); index++) {
      ResolvedParameterInput input = resolvedInputs.get(index);
      VariableStorage storage = matchedPlan.storages().get(index);
      if (storage == null) {
        int derivedIndex = autoOffset + index;
        if (derivedIndex >= derivedParams.length) {
          throw new IllegalArgumentException(
              "derived parameter storage missing at ordinal " + index);
        }
        storage = derivedParams[derivedIndex].getVariableStorage();
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
      String comment = matchedPlan.comments().get(index);
      if (comment != null) {
        customParam.setComment(comment);
      }
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

  static Function reconcileCustomStorageAfterSignature(
      GhidraSession context,
      Function updated,
      boolean explicitCallingConvention,
      VariableStorageReference returnStorage,
      Boolean customStorage,
      boolean oldCustomStorage,
      VariableStorage oldReturnStorage,
      List<ParameterSnapshot> oldParameters) {
    if (returnStorage != null && Boolean.FALSE.equals(customStorage)) {
      throw new DataTypeMutationValidationException(
          CUSTOM_STORAGE_TARGET,
          "explicit storage cannot be combined with hasCustomVariableStorage=false");
    }
    Program program = context.currentProgram();
    FunctionStorageSupport.ParsedStorage explicitReturnStorage =
        parseAndValidateStorage(
            program,
            updated.getReturnType(),
            returnStorage,
            "returnStorage",
            RETURN_STORAGE_TARGET);

    boolean wantCustom =
        explicitReturnStorage != null
            || Boolean.TRUE.equals(customStorage)
            || (customStorage == null && oldCustomStorage && !explicitCallingConvention);
    if (!wantCustom) {
      return updated;
    }

    List<Parameter> appliedParams = new ArrayList<>();
    for (Parameter parameter : updated.getParameters()) {
      if (explicitReturnStorage != null && isReturnStoragePointer(parameter)) {
        continue;
      }
      appliedParams.add(parameter);
    }
    List<ResolvedParameterInput> appliedInputs = new ArrayList<>(appliedParams.size());
    for (Parameter param : appliedParams) {
      appliedInputs.add(
          new ResolvedParameterInput(param.getName(), param.getFormalDataType(), null));
    }
    MatchedParameterPlan matchedPlan =
        matchCustomParameterStorages(updated, appliedInputs, oldParameters, oldCustomStorage);

    VariableStorage targetReturnStorage =
        resolveTargetReturnStorage(
            updated,
            updated.getReturnType(),
            explicitReturnStorage,
            oldCustomStorage,
            oldReturnStorage);
    ReturnParameterImpl returnParameter =
        FunctionStorageSupport.createReturn(program, updated.getReturnType(), targetReturnStorage);

    List<Variable> customParameters = new ArrayList<>(appliedParams.size());
    for (int index = 0; index < appliedParams.size(); index++) {
      Parameter current = appliedParams.get(index);
      VariableStorage chosen = matchedPlan.storages().get(index);
      if (chosen == null) {
        chosen = current.getVariableStorage();
      }
      ParameterImpl rebuilt =
          FunctionStorageSupport.createParameter(
              program,
              current.getName(),
              index,
              current.getFormalDataType(),
              chosen,
              SourceType.USER_DEFINED,
              "parameter " + index);
      String preservedComment = matchedPlan.comments().get(index);
      if (preservedComment != null) {
        rebuilt.setComment(preservedComment);
      } else if (current.getComment() != null) {
        rebuilt.setComment(current.getComment());
      }
      customParameters.add(rebuilt);
    }

    Function result =
        applySignatureUpdate(
            context,
            updated,
            FunctionUpdateType.CUSTOM_STORAGE,
            null,
            returnParameter,
            customParameters,
            "unable to preserve custom storage after C signature update");
    FunctionStorageSupport.requireValidCustomSignature(result);
    FunctionStorageSupport.requireSignatureApplied(result, returnParameter, customParameters);
    if (explicitReturnStorage != null) {
      FunctionMutationSupport.requireStorageApplied(
          "returnStorage",
          explicitReturnStorage.serialization(),
          result.getReturn().getVariableStorage());
    }
    return result;
  }

  private static List<ResolvedParameterInput> resolveParameterInputs(
      Program program,
      List<ParameterPatch> parameterPatches,
      FunctionMutations.ParameterDataTypeResolver dataTypeResolver) {
    List<ResolvedParameterInput> resolved = new ArrayList<>(parameterPatches.size());
    Set<String> seenNames = new HashSet<>();
    for (int index = 0; index < parameterPatches.size(); index++) {
      String itemTarget = "/patch/parameters/" + index;
      ParameterPatch patchItem = parameterPatches.get(index);
      if (patchItem == null) {
        throw new DataTypeMutationValidationException(
            itemTarget, "parameter entry must not be null");
      }
      String name = patchItem.name();
      if (name != null
          && !SymbolUtilities.isDefaultParameterName(name)
          && !seenNames.add(name)) {
        throw new DataTypeMutationValidationException(
            itemTarget + "/name", "duplicate parameter name: " + name);
      }
      DataType paramType =
          resolveParameterDataType(dataTypeResolver, patchItem.dataType(), itemTarget + "/data_type");
      FunctionStorageSupport.ParsedStorage explicitStorage =
          parseAndValidateStorage(
              program,
              paramType,
              patchItem.storage(),
              "parameters[" + index + "].storage",
              itemTarget + "/storage");
      resolved.add(new ResolvedParameterInput(name, paramType, explicitStorage));
    }
    return resolved;
  }

  private static DataType resolveReturnDataType(
      FunctionMutations.ParameterDataTypeResolver dataTypeResolver, DataTypeReference input) {
    try {
      return FunctionMutationSupport.requireDataType(dataTypeResolver, input);
    } catch (DataTypeMutationValidationException ex) {
      throw ex;
    } catch (IllegalArgumentException ex) {
      throw new DataTypeMutationValidationException(RETURN_TYPE_TARGET, ex.getMessage(), ex);
    }
  }

  private static DataType resolveParameterDataType(
      FunctionMutations.ParameterDataTypeResolver dataTypeResolver,
      DataTypeReference input,
      String target) {
    try {
      DataType resolved = FunctionMutationSupport.requireParameterDataType(dataTypeResolver, input);
      if (FunctionStorageSupport.isVoid(resolved)) {
        throw new DataTypeMutationValidationException(
            target, "parameter data type cannot be void");
      }
      return resolved;
    } catch (DataTypeMutationValidationException ex) {
      throw ex;
    } catch (IllegalArgumentException ex) {
      throw new DataTypeMutationValidationException(target, ex.getMessage(), ex);
    }
  }

  private static FunctionStorageSupport.ParsedStorage parseAndValidateStorage(
      Program program,
      DataType dataType,
      VariableStorageReference storageInput,
      String field,
      String target) {
    if (storageInput == null) {
      return null;
    }
    try {
      FunctionStorageSupport.ParsedStorage parsed =
          FunctionStorageSupport.parseExplicit(program, storageInput, field);
      FunctionStorageSupport.requireCompatible(dataType, parsed.storage(), field);
      return parsed;
    } catch (IllegalArgumentException ex) {
      throw new DataTypeMutationValidationException(target, ex.getMessage(), ex);
    }
  }

  private static MatchedParameterPlan matchCustomParameterStorages(
      Function function,
      List<ResolvedParameterInput> inputs,
      List<ParameterSnapshot> oldParameters,
      boolean oldCustomStorage) {
    int count = inputs.size();
    VariableStorage[] storages = new VariableStorage[count];
    String[] comments = new String[count];
    Set<Integer> claimedOld = new HashSet<>();
    Set<String> allExplicitNames = new HashSet<>();
    for (ResolvedParameterInput input : inputs) {
      if (isExplicitName(input.name())) {
        allExplicitNames.add(input.name());
      }
    }

    // Pass 1: assign explicit storages and match unique non-default parameter names first so
    // reordered or shifted parameters never lose their custom storage to ordinal fallback.
    for (int index = 0; index < count; index++) {
      ResolvedParameterInput input = inputs.get(index);
      int matchedNameIndex = findUniqueOldByName(oldParameters, claimedOld, input.name());
      if (matchedNameIndex >= 0) {
        claimedOld.add(matchedNameIndex);
        ParameterSnapshot snapshot = oldParameters.get(matchedNameIndex);
        comments[index] = snapshot.comment();
        if (input.explicitStorage() != null) {
          storages[index] = input.explicitStorage().storage();
        } else if (oldCustomStorage) {
          storages[index] = adaptCompatibleStorage(function, input.dataType(), snapshot.storage());
        }
      } else if (input.explicitStorage() != null) {
        storages[index] = input.explicitStorage().storage();
      }
    }

    // Pass 2: ordinal fallback for unnamed or renamed-in-place parameters when the old parameter
    // at the same formal ordinal was not claimed and did not move to another ordinal by name.
    if (oldCustomStorage) {
      List<Integer> formalOldIndices = formalOldParameterIndices(oldParameters);
      for (int index = 0; index < count; index++) {
        if (storages[index] != null || index >= formalOldIndices.size()) {
          continue;
        }
        int oldIndex = formalOldIndices.get(index);
        if (claimedOld.contains(oldIndex)) {
          continue;
        }
        ParameterSnapshot snapshot = oldParameters.get(oldIndex);
        if (isExplicitName(snapshot.name()) && allExplicitNames.contains(snapshot.name())) {
          continue;
        }
        VariableStorage adapted =
            adaptCompatibleStorage(function, inputs.get(index).dataType(), snapshot.storage());
        if (adapted != null) {
          claimedOld.add(oldIndex);
          storages[index] = adapted;
          if (comments[index] == null) {
            comments[index] = snapshot.comment();
          }
        }
      }
    }

    boolean needsDynamicDerivation = false;
    for (VariableStorage storage : storages) {
      if (storage == null) {
        needsDynamicDerivation = true;
        break;
      }
    }
    return new MatchedParameterPlan(
        Arrays.asList(storages), Arrays.asList(comments), needsDynamicDerivation);
  }

  private static int findUniqueOldByName(
      List<ParameterSnapshot> oldParameters, Set<Integer> claimedOld, String candidateName) {
    if (!isExplicitName(candidateName)) {
      return -1;
    }
    int matchIndex = -1;
    int matchCount = 0;
    for (int index = 0; index < oldParameters.size(); index++) {
      ParameterSnapshot snapshot = oldParameters.get(index);
      if (snapshot.autoParameter() || claimedOld.contains(index)) {
        continue;
      }
      if (candidateName.equals(snapshot.name())) {
        matchIndex = index;
        matchCount++;
      }
    }
    return matchCount == 1 ? matchIndex : -1;
  }

  private static List<Integer> formalOldParameterIndices(List<ParameterSnapshot> oldParameters) {
    List<Integer> indices = new ArrayList<>(oldParameters.size());
    for (int index = 0; index < oldParameters.size(); index++) {
      if (!oldParameters.get(index).autoParameter()) {
        indices.add(index);
      }
    }
    return indices;
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
            new ParameterImpl(
                input.name(),
                input.dataType(),
                VariableStorage.UNASSIGNED_STORAGE,
                program,
                SourceType.USER_DEFINED);
        int commentDonor = findUniqueOldByName(oldParameters, claimedComments, input.name());
        if (commentDonor >= 0) {
          claimedComments.add(commentDonor);
          String comment = oldParameters.get(commentDonor).comment();
          if (comment != null) {
            parameter.setComment(comment);
          }
        }
        result.add(parameter);
      } catch (InvalidInputException error) {
        throw new DataTypeMutationValidationException(
            "/patch/parameters/" + index,
            "unable to construct parameter " + index + ": " + error.getMessage(),
            error);
      }
    }
    return result;
  }

  private static VariableStorage resolveTargetReturnStorage(
      Function working,
      DataType targetReturnType,
      FunctionStorageSupport.ParsedStorage explicitReturnStorage,
      boolean oldCustomStorage,
      VariableStorage oldReturnStorage) {
    if (explicitReturnStorage != null) {
      return explicitReturnStorage.storage();
    }
    if (FunctionStorageSupport.isVoid(targetReturnType)) {
      return VariableStorage.VOID_STORAGE;
    }
    if (oldCustomStorage) {
      VariableStorage adapted = adaptCompatibleStorage(working, targetReturnType, oldReturnStorage);
      if (adapted != null) {
        return adapted;
      }
    }
    return working.getReturn().getVariableStorage();
  }

  private static VariableStorage adaptCompatibleStorage(
      Function function, DataType dataType, VariableStorage storage) {
    if (FunctionStorageSupport.isVoid(dataType) || !isRealCustomStorage(storage)) {
      return null;
    }
    int length = dataType.getLength();
    if (length <= 0) {
      return null;
    }
    if (storage.size() == length || dataType instanceof AbstractFloatDataType) {
      return storage;
    }
    try {
      VariableStorage resized = VariableUtilities.resizeStorage(storage, dataType, true, function);
      if (isRealCustomStorage(resized)
          && (resized.size() == length || dataType instanceof AbstractFloatDataType)) {
        return resized;
      }
    } catch (InvalidInputException | RuntimeException ignored) {
      // Fall back to dynamic ABI derivation when prior storage cannot fit the new data type.
    }
    return null;
  }

  private static boolean isRealCustomStorage(VariableStorage storage) {
    return storage != null
        && storage.isValid()
        && !storage.isBadStorage()
        && !storage.isUnassignedStorage()
        && !storage.isVoidStorage()
        && !storage.isAutoStorage()
        && !storage.isForcedIndirect();
  }

  private static boolean isExplicitName(String name) {
    return name != null && !name.isBlank() && !SymbolUtilities.isDefaultParameterName(name);
  }

  private static int countLeadingAutoParameters(Parameter[] parameters) {
    int count = 0;
    while (count < parameters.length && parameters[count].isAutoParameter()) {
      count++;
    }
    return count;
  }

  private static boolean isReturnStoragePointer(Parameter parameter) {
    return (parameter.isAutoParameter()
            && parameter.getAutoParameterType() == AutoParameterType.RETURN_STORAGE_PTR)
        || (Function.RETURN_PTR_PARAM_NAME.equals(parameter.getName())
            && parameter.getDataType() instanceof Pointer);
  }

  private static Function applySignatureUpdate(
      GhidraSession context,
      Function function,
      FunctionUpdateType updateType,
      String callingConvention,
      Variable returnParameter,
      List<? extends Variable> parameters,
      String failureMessage) {
    context.runCommand(
        new UpdateFunctionCommand(
            function,
            updateType,
            callingConvention,
            returnParameter,
            parameters,
            SourceType.USER_DEFINED,
            false),
        failureMessage);
    return FunctionMutationSupport.refreshFunction(context, function, "signature update");
  }

  private record ResolvedParameterInput(
      String name, DataType dataType, FunctionStorageSupport.ParsedStorage explicitStorage) {}

  private record MatchedParameterPlan(
      List<VariableStorage> storages, List<String> comments, boolean needsDynamicDerivation) {}
}
