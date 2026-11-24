package app.byteland.ghidra.adapter.ghidra.function;

import app.byteland.ghidra.adapter.ghidra.GhidraCTypeParser;
import app.byteland.ghidra.adapter.ghidra.GhidraCTypeParser.ParsedPrototype;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.ScriptSymbolRenamer;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.function.FunctionService.FunctionAttributePatch;
import app.byteland.ghidra.service.function.FunctionService.ParameterPatch;
import app.byteland.ghidra.service.function.VariableStorageReference;
import ghidra.app.cmd.function.UpdateFunctionCommand;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.PrototypeModel;
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
import ghidra.util.exception.InvalidInputException;
import java.util.ArrayList;
import java.util.List;
import java.util.function.BiConsumer;

final class FunctionMutations {
  @FunctionalInterface
  interface ParameterDataTypeResolver {
    DataType resolve(DataTypeReference input);
  }

  private record ResolvedParameter(
      String name, DataType dataType, VariableStorageReference storage) {}

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
    FunctionAttributePatch attributePatch =
        attributes == null ? FunctionAttributePatch.empty() : attributes;
    Function updated = function;

    ParsedPrototype parsedPrototype =
        signature == null
            ? null
            : GhidraCTypeParser.parseFunctionPrototype(
                context.currentProgram().getDataTypeManager(), updated.getSignature(), signature);

    String effectiveName =
        newName != null && !newName.isBlank()
            ? newName
            : parsedPrototype != null ? parsedPrototype.name() : null;

    if (effectiveName != null
        && !effectiveName.isBlank()
        && !updated.getName().equals(effectiveName)) {
      Symbol symbol = context.script().getSymbolAt(updated.getEntryPoint());
      if (symbol == null) {
        throw new IllegalArgumentException("function symbol not found");
      }
      ScriptSymbolRenamer.rename(context, symbol, effectiveName);
      updated = context.script().getFunctionAt(updated.getEntryPoint());
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

    String effectiveCallingConvention =
        callingConvention != null && !callingConvention.isBlank()
            ? callingConvention
            : parsedPrototype != null ? parsedPrototype.callingConvention() : null;

    List<ResolvedParameter> resolvedParameters =
        resolveRequestedParameters(parameters, parsedPrototype, dataTypeResolver);

    if (resolvedParameters != null) {
      DataType targetReturnType =
          parsedPrototype != null
              ? parsedPrototype.returnType()
              : returnType != null
                  ? FunctionMutationSupport.requireDataType(dataTypeResolver, returnType)
                  : returnStorage != null
                      ? updated.getReturn().getFormalDataType()
                      : updated.getReturnType();
      updated =
          patchSignatureWithParameters(
              context,
              updated,
              targetReturnType,
              returnStorage,
              resolvedParameters,
              effectiveCallingConvention,
              attributePatch.hasCustomVariableStorage());
    } else {
      updated =
          patchSignature(
              context,
              updated,
              returnType,
              returnStorage,
              effectiveCallingConvention,
              attributePatch.hasCustomVariableStorage(),
              dataTypeResolver);
    }

    Boolean effectiveNoReturn =
        attributePatch.hasNoReturn() != null
            ? attributePatch.hasNoReturn()
            : (parsedPrototype != null && parsedPrototype.hasNoReturn() ? Boolean.TRUE : null);
    Boolean effectiveVarArgs =
        attributePatch.hasVarArgs() != null
            ? attributePatch.hasVarArgs()
            : (parsedPrototype != null ? parsedPrototype.hasVarArgs() : null);

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
            effectiveNoReturn,
            Function::hasNoReturn,
            Function::setNoReturn);
    updated =
        patchAttribute(
            context,
            updated,
            "hasVarArgs",
            effectiveVarArgs,
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

  @SuppressWarnings("PMD.ReturnEmptyCollectionRatherThanNull")
  private static List<ResolvedParameter> resolveRequestedParameters(
      List<ParameterPatch> parameters,
      ParsedPrototype parsedPrototype,
      ParameterDataTypeResolver dataTypeResolver) {
    if (parsedPrototype != null) {
      List<ResolvedParameter> resolved = new ArrayList<>(parsedPrototype.parameters().size());
      for (ParameterDefinition param : parsedPrototype.parameters()) {
        resolved.add(new ResolvedParameter(param.getName(), param.getDataType(), null));
      }
      return List.copyOf(resolved);
    }
    if (parameters == null) {
      return null;
    }
    List<ResolvedParameter> resolved = new ArrayList<>(parameters.size());
    for (ParameterPatch param : parameters) {
      DataType dt = FunctionMutationSupport.requireParameterDataType(dataTypeResolver, param.dataType());
      resolved.add(new ResolvedParameter(param.name(), dt, param.storage()));
    }
    return List.copyOf(resolved);
  }

  private static Function patchSignatureWithParameters(
      GhidraSession context,
      Function function,
      DataType targetReturnType,
      VariableStorageReference returnStorage,
      List<ResolvedParameter> requestedParameters,
      String callingConvention,
      Boolean customStorage) {
    boolean hasReturnStorage = returnStorage != null;
    boolean anyParamHasStorage =
        requestedParameters.stream().anyMatch(param -> param.storage() != null);
    if ((hasReturnStorage || anyParamHasStorage) && Boolean.FALSE.equals(customStorage)) {
      throw new IllegalArgumentException(
          "explicit storage cannot be combined with hasCustomVariableStorage=false");
    }

    Program program = context.currentProgram();
    boolean hasCallingConvention = callingConvention != null && !callingConvention.isBlank();
    boolean oldCustomStorage = function.hasCustomVariableStorage();
    boolean finalCustomStorage =
        hasReturnStorage
            || anyParamHasStorage
            || (customStorage != null ? customStorage : oldCustomStorage);

    FunctionStorageSupport.ParsedStorage explicitReturnStorage =
        FunctionStorageSupport.parseExplicit(program, returnStorage, "returnStorage");
    if (explicitReturnStorage != null) {
      FunctionStorageSupport.requireCompatible(
          targetReturnType, explicitReturnStorage.storage(), "returnStorage");
    }

    if (!finalCustomStorage) {
      List<Variable> dynamicParameters = new ArrayList<>(requestedParameters.size());
      for (int index = 0; index < requestedParameters.size(); index++) {
        ResolvedParameter param = requestedParameters.get(index);
        String name = param.name() == null || param.name().isBlank() ? null : param.name();
        try {
          dynamicParameters.add(
              new ParameterImpl(name, param.dataType(), program, SourceType.USER_DEFINED));
        } catch (InvalidInputException ex) {
          throw new IllegalArgumentException(
              "unable to construct parameter " + index + ": " + ex.getMessage(), ex);
        }
      }
      Function updated =
          applySignatureUpdate(
              context,
              function,
              FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
              hasCallingConvention ? callingConvention : null,
              FunctionStorageSupport.createDynamicReturn(program, targetReturnType),
              dynamicParameters,
              SourceType.USER_DEFINED,
              "unable to update function parameters");
      if (updated.hasCustomVariableStorage()) {
        throw new IllegalArgumentException("unable to disable custom variable storage");
      }
      return updated;
    }

    PrototypeModel prototypeModel = resolvePrototypeModel(program, callingConvention, function);
    VariableStorage[] abiLocations =
        computeAbiLocations(program, prototypeModel, targetReturnType, requestedParameters);

    ReturnParameterImpl returnParameter =
        buildCustomReturnParameter(
            program,
            function,
            targetReturnType,
            explicitReturnStorage,
            oldCustomStorage,
            abiLocations[0]);

    List<Parameter> existingNonAuto = nonAutoParameters(function);
    List<Variable> customParameters = new ArrayList<>(requestedParameters.size());
    List<String> exactSerializations = new ArrayList<>(requestedParameters.size());

    for (int index = 0; index < requestedParameters.size(); index++) {
      ResolvedParameter param = requestedParameters.get(index);
      String field = "parameters[" + index + "]";
      String name = param.name() == null || param.name().isBlank() ? null : param.name();
      VariableStorage paramStorage;
      String expectedExactSerialization = null;

      if (param.storage() != null) {
        FunctionStorageSupport.ParsedStorage parsed =
            FunctionStorageSupport.parseExplicit(program, param.storage(), field + ".storage");
        paramStorage = parsed.storage();
        if (param.storage() instanceof VariableStorageReference.Serialization
            && paramStorage.size() != param.dataType().getLength()
            && !FunctionStorageSupport.isFloat(param.dataType())) {
          paramStorage =
              FunctionStorageSupport.resizeStorage(
                  function, param.dataType(), paramStorage, field + ".storage");
        }
        FunctionStorageSupport.requireCompatible(
            param.dataType(), paramStorage, field + ".storage");
        expectedExactSerialization = paramStorage.getSerializationString();
      } else if (oldCustomStorage && index < existingNonAuto.size()) {
        paramStorage = existingNonAuto.get(index).getVariableStorage();
        if (paramStorage.size() != param.dataType().getLength()
            && !FunctionStorageSupport.isFloat(param.dataType())) {
          paramStorage =
              FunctionStorageSupport.resizeStorage(
                  function, param.dataType(), paramStorage, field + ".storage");
        }
      } else {
        paramStorage =
            selectNonOverlappingAbiStorage(
                program, prototypeModel, param.dataType(), abiLocations[index + 1], customParameters);
      }

      ParameterImpl created =
          FunctionStorageSupport.createParameter(
              program,
              name,
              index,
              param.dataType(),
              paramStorage,
              SourceType.USER_DEFINED,
              "parameter " + index);
      customParameters.add(created);
      exactSerializations.add(expectedExactSerialization);
    }

    Function updated =
        applySignatureUpdate(
            context,
            function,
            FunctionUpdateType.CUSTOM_STORAGE,
            hasCallingConvention ? callingConvention : null,
            returnParameter,
            customParameters,
            SourceType.USER_DEFINED,
            "unable to apply custom function parameters");
    FunctionStorageSupport.requireValidCustomSignature(updated);
    FunctionStorageSupport.requireSignatureApplied(updated, returnParameter, customParameters);
    if (explicitReturnStorage != null) {
      FunctionMutationSupport.requireStorageApplied(
          "returnStorage",
          explicitReturnStorage.serialization(),
          updated.getReturn().getVariableStorage());
    }
    for (int index = 0; index < exactSerializations.size(); index++) {
      String expectedSerialization = exactSerializations.get(index);
      if (expectedSerialization != null) {
        FunctionMutationSupport.requireStorageApplied(
            "parameters[" + index + "].storage",
            expectedSerialization,
            updated.getParameter(index).getVariableStorage());
      }
    }
    return updated;
  }

  private static ReturnParameterImpl buildCustomReturnParameter(
      Program program,
      Function function,
      DataType targetReturnType,
      FunctionStorageSupport.ParsedStorage explicitReturnStorage,
      boolean oldCustomStorage,
      VariableStorage abiReturnStorage) {
    if (explicitReturnStorage != null) {
      return FunctionStorageSupport.createReturn(
          program, targetReturnType, explicitReturnStorage.storage());
    }
    if (FunctionStorageSupport.isVoid(targetReturnType)) {
      return FunctionStorageSupport.createReturn(
          program, targetReturnType, VariableStorage.VOID_STORAGE);
    }
    VariableStorage currentStorage = function.getReturn().getVariableStorage();
    boolean hasReusableCustomReturn =
        oldCustomStorage
            && currentStorage != null
            && !currentStorage.isVoidStorage()
            && !currentStorage.isUnassignedStorage();
    if (hasReusableCustomReturn) {
      if (!function.getReturnType().isEquivalent(targetReturnType)
          && currentStorage.size() != targetReturnType.getLength()
          && !FunctionStorageSupport.isFloat(targetReturnType)) {
        currentStorage =
            FunctionStorageSupport.resizeStorage(
                function, targetReturnType, currentStorage, "return storage");
      }
      return FunctionStorageSupport.createReturn(program, targetReturnType, currentStorage);
    }
    return FunctionStorageSupport.createReturn(program, targetReturnType, abiReturnStorage);
  }

  private static PrototypeModel resolvePrototypeModel(
      Program program, String callingConvention, Function function) {
    CompilerSpec spec = program.getCompilerSpec();
    if (callingConvention != null && !callingConvention.isBlank()) {
      if (CompilerSpec.CALLING_CONVENTION_default.equals(callingConvention)) {
        return spec.getDefaultCallingConvention();
      }
      PrototypeModel model = spec.getCallingConvention(callingConvention);
      if (model == null) {
        throw new IllegalArgumentException("unknown calling convention: " + callingConvention);
      }
      return model;
    }
    PrototypeModel current = function.getCallingConvention();
    return current != null ? current : spec.getDefaultCallingConvention();
  }

  private static VariableStorage[] computeAbiLocations(
      Program program,
      PrototypeModel model,
      DataType returnType,
      List<ResolvedParameter> parameters) {
    DataType[] types = new DataType[parameters.size() + 1];
    types[0] = returnType;
    for (int i = 0; i < parameters.size(); i++) {
      types[i + 1] = parameters.get(i).dataType();
    }
    return model.getStorageLocations(program, types, false);
  }

  private static VariableStorage selectNonOverlappingAbiStorage(
      Program program,
      PrototypeModel model,
      DataType paramType,
      VariableStorage preferred,
      List<Variable> assigned) {
    if (!intersectsAny(preferred, assigned)) {
      return preferred;
    }
    int maxProbe = assigned.size() + 16;
    DataType[] probeTypes = new DataType[maxProbe + 1];
    probeTypes[0] = VoidDataTypeInstance.VOID;
    for (int i = 1; i <= maxProbe; i++) {
      probeTypes[i] = paramType;
    }
    VariableStorage[] candidates = model.getStorageLocations(program, probeTypes, false);
    for (int i = 1; i < candidates.length; i++) {
      if (!intersectsAny(candidates[i], assigned)) {
        return candidates[i];
      }
    }
    return preferred;
  }

  private static final class VoidDataTypeInstance {
    static final DataType VOID = ghidra.program.model.data.VoidDataType.dataType;
  }

  private static boolean intersectsAny(VariableStorage candidate, List<Variable> assigned) {
    if (candidate == null) return false;
    for (Variable existing : assigned) {
      if (existing.getVariableStorage() != null
          && candidate.intersects(existing.getVariableStorage())) {
        return true;
      }
    }
    return false;
  }

  private static List<Parameter> nonAutoParameters(Function function) {
    List<Parameter> result = new ArrayList<>();
    for (Parameter parameter : function.getParameters()) {
      if (!parameter.isAutoParameter()) {
        result.add(parameter);
      }
    }
    return result;
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
