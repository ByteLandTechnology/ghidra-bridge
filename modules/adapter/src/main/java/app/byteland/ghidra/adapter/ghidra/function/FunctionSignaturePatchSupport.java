package app.byteland.ghidra.adapter.ghidra.function;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.function.CFunctionSignatureParser.ParsedFunctionSignature;
import app.byteland.ghidra.adapter.ghidra.function.FunctionParameterPatchSupport.MatchedParameterPlan;
import app.byteland.ghidra.adapter.ghidra.function.FunctionParameterPatchSupport.ParameterSnapshot;
import app.byteland.ghidra.adapter.ghidra.function.FunctionParameterPatchSupport.ResolvedParameterInput;
import app.byteland.ghidra.service.function.VariableStorageReference;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.function.FunctionRenameOption;
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
import java.util.ArrayList;
import java.util.List;

/**
 * Applies C prototype strings to functions and reconciles custom variable storage.
 */
final class FunctionSignaturePatchSupport {
  private FunctionSignaturePatchSupport() {}

  static Function applyTextSignature(
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
    List<ParameterSnapshot> oldParameters =
        FunctionParameterPatchSupport.snapshotParameters(function);

    ParsedFunctionSignature parsed =
        CFunctionSignatureParser.parse(program.getDataTypeManager(), function, signatureText);
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

    List<Parameter> appliedParams = new ArrayList<>();
    for (Parameter parameter : updated.getParameters()) {
      if (explicitReturnStorage != null && isReturnStoragePointer(parameter)) {
        continue;
      }
      appliedParams.add(parameter);
    }
    List<ResolvedParameterInput> appliedInputs = new ArrayList<>(appliedParams.size());
    for (Parameter parameter : appliedParams) {
      appliedInputs.add(
          new ResolvedParameterInput(parameter.getName(), parameter.getFormalDataType(), null));
    }
    MatchedParameterPlan matchedPlan =
        FunctionParameterPatchSupport.matchCustomParameterStorages(
            appliedInputs, oldParameters, oldCustomStorage);

    boolean compatiblePriorCustomSignature =
        !parsed.explicitCallingConvention()
            && !matchedPlan.needsDynamicDerivation()
            && (FunctionStorageSupport.isVoid(updated.getReturnType())
                || FunctionParameterPatchSupport.isStorageCompatible(
                    updated.getReturnType(), oldReturnStorage));

    boolean wantCustom =
        explicitReturnStorage != null
            || Boolean.TRUE.equals(customStorage)
            || (customStorage == null && oldCustomStorage && compatiblePriorCustomSignature);
    if (!wantCustom) {
      return updated;
    }

    VariableStorage targetReturnStorage;
    if (explicitReturnStorage != null) {
      targetReturnStorage = explicitReturnStorage.storage();
    } else if (FunctionStorageSupport.isVoid(updated.getReturnType())) {
      targetReturnStorage = VariableStorage.VOID_STORAGE;
    } else if (oldCustomStorage
        && FunctionParameterPatchSupport.isStorageCompatible(
            updated.getReturnType(), oldReturnStorage)) {
      targetReturnStorage = oldReturnStorage;
    } else {
      targetReturnStorage = updated.getReturn().getVariableStorage();
    }

    ReturnParameterImpl returnParam =
        FunctionStorageSupport.createReturn(program, updated.getReturnType(), targetReturnStorage);
    List<Variable> customParams = new ArrayList<>(appliedParams.size());
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
      customParams.add(rebuilt);
    }

    updated =
        FunctionMutations.applySignatureUpdate(
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

  private static boolean isReturnStoragePointer(Parameter parameter) {
    return (parameter.isAutoParameter()
            && parameter.getAutoParameterType() == AutoParameterType.RETURN_STORAGE_PTR)
        || (Function.RETURN_PTR_PARAM_NAME.equals(parameter.getName())
            && parameter.getDataType() instanceof Pointer);
  }
}
