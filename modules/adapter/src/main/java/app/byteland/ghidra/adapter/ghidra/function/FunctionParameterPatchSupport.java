package app.byteland.ghidra.adapter.ghidra.function;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.function.FunctionService.ParameterPatch;
import app.byteland.ghidra.service.function.VariableStorageReference;
import ghidra.program.model.data.AbstractFloatDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.exception.InvalidInputException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Applies atomic parameter list replacements and preserves compatible custom variable storage.
 */
final class FunctionParameterPatchSupport {
  private FunctionParameterPatchSupport() {}

  record ParameterSnapshot(
      String name,
      DataType dataType,
      VariableStorage storage,
      String comment,
      boolean autoParameter) {}

  record ResolvedParameterInput(
      String name, DataType dataType, FunctionStorageSupport.ParsedStorage explicitStorage) {}

  record MatchedParameterPlan(
      List<VariableStorage> storages, List<String> comments, boolean needsDynamicDerivation) {}

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
      throw new IllegalArgumentException(
          "explicit storage cannot be combined with hasCustomVariableStorage=false");
    }

    boolean oldCustomStorage = function.hasCustomVariableStorage();
    VariableStorage oldReturnStorage = function.getReturn().getVariableStorage();
    List<ParameterSnapshot> oldParameters = snapshotParameters(function);
    SourceType signatureSource = FunctionMutations.signatureSource(function);

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
          FunctionMutations.applySignatureUpdate(
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

    MatchedParameterPlan matchedPlan =
        matchCustomParameterStorages(resolvedInputs, oldParameters, oldCustomStorage);
    boolean returnNeedsDerivation =
        explicitReturnStorage == null
            && !FunctionStorageSupport.isVoid(targetReturnType)
            && (!oldCustomStorage || !isStorageCompatible(targetReturnType, oldReturnStorage));

    Function working = function;
    if (matchedPlan.needsDynamicDerivation() || returnNeedsDerivation) {
      working =
          FunctionMutations.applySignatureUpdate(
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
      String preservedComment = matchedPlan.comments().get(index);
      if (preservedComment != null) {
        customParam.setComment(preservedComment);
      }
      customParameters.add(customParam);
    }

    working =
        FunctionMutations.applySignatureUpdate(
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

  static MatchedParameterPlan matchCustomParameterStorages(
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

    for (int index = 0; index < count; index++) {
      ResolvedParameterInput input = inputs.get(index);
      int matchedNameIndex = findUniqueOldByName(oldParameters, claimedOld, input.name());
      if (matchedNameIndex >= 0) {
        ParameterSnapshot snapshot = oldParameters.get(matchedNameIndex);
        claimedOld.add(matchedNameIndex);
        comments[index] = snapshot.comment();
        if (input.explicitStorage() != null) {
          storages[index] = input.explicitStorage().storage();
        } else if (oldCustomStorage && isStorageCompatible(input.dataType(), snapshot.storage())) {
          storages[index] = snapshot.storage();
        }
      } else if (input.explicitStorage() != null) {
        storages[index] = input.explicitStorage().storage();
      }
    }

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
        if (isStorageCompatible(inputs.get(index).dataType(), snapshot.storage())) {
          claimedOld.add(oldIndex);
          storages[index] = snapshot.storage();
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

  static boolean isStorageCompatible(DataType dataType, VariableStorage storage) {
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

  private static List<ResolvedParameterInput> resolveParameterInputs(
      Program program,
      List<ParameterPatch> parameterPatches,
      FunctionMutations.ParameterDataTypeResolver dataTypeResolver) {
    List<ResolvedParameterInput> resolved = new ArrayList<>(parameterPatches.size());
    Set<String> seenNames = new HashSet<>();
    for (int index = 0; index < parameterPatches.size(); index++) {
      ParameterPatch patchItem = parameterPatches.get(index);
      if (patchItem == null) {
        throw new IllegalArgumentException("parameters[" + index + "] must not be null");
      }
      String name = patchItem.name();
      if (isExplicitName(name) && !seenNames.add(name)) {
        throw new IllegalArgumentException("duplicate parameter name: " + name);
      }
      DataType paramType =
          FunctionMutationSupport.requireParameterDataType(dataTypeResolver, patchItem.dataType());
      if (FunctionStorageSupport.isVoid(paramType)) {
        throw new IllegalArgumentException(
            "parameters[" + index + "] data type must not be void");
      }
      FunctionStorageSupport.ParsedStorage explicitStorage =
          FunctionStorageSupport.parseExplicit(
              program, patchItem.storage(), "parameters[" + index + "].storage");
      if (explicitStorage != null) {
        FunctionStorageSupport.requireCompatible(
            paramType, explicitStorage.storage(), "parameters[" + index + "].storage");
      }
      resolved.add(new ResolvedParameterInput(name, paramType, explicitStorage));
    }
    return resolved;
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
        throw new IllegalArgumentException(
            "unable to construct parameter " + index + ": " + error.getMessage(), error);
      }
    }
    return result;
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

  private static int countLeadingAutoParameters(Parameter[] parameters) {
    int count = 0;
    while (count < parameters.length && parameters[count].isAutoParameter()) {
      count++;
    }
    return count;
  }

  private static boolean isExplicitName(String name) {
    return name != null && !name.isBlank() && !SymbolUtilities.isDefaultParameterName(name);
  }
}
