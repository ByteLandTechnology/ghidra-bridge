package app.byteland.ghidra.adapter.ghidra.function;

import app.byteland.ghidra.adapter.ghidra.GhidraDataTypeReferences;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.decompilation.DecompilerLocalSymbols;
import app.byteland.ghidra.adapter.ghidra.decompilation.DecompilerPool;
import app.byteland.ghidra.service.TransactionExecutionException;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.function.FunctionResource;
import app.byteland.ghidra.service.function.VariableStorageReference;
import ghidra.app.cmd.function.SetVariableDataTypeCmd;
import ghidra.app.cmd.function.SetVariableNameCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableFilter;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.DynamicEntry;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;

final class FunctionLocalVariableMutations {
  private FunctionLocalVariableMutations() {}

  static FunctionResource.LocalVariableResource patchLocalVariable(
      GhidraSession context,
      DecompilerPool decompilerPool,
      Function function,
      String variableName,
      String newName,
      DataTypeReference newDataType,
      FunctionMutations.ParameterDataTypeResolver dataTypeResolver) {
    Optional<Variable> existing =
        FunctionVariableMutationSupport.findLocalVariable(function, variableName);
    if (existing.isPresent()) {
      return patchDatabaseLocal(
          context, function, existing.get(), newName, newDataType, dataTypeResolver);
    }
    return patchDecompilerLocal(
        context,
        decompilerPool,
        function,
        variableName,
        newName,
        newDataType,
        dataTypeResolver);
  }

  private static FunctionResource.LocalVariableResource patchDatabaseLocal(
      GhidraSession context,
      Function function,
      Variable variable,
      String newName,
      DataTypeReference newDataType,
      FunctionMutations.ParameterDataTypeResolver dataTypeResolver) {
    Function currentFunction = function;
    Variable currentVariable = variable;
    if (newName != null && !newName.isBlank()) {
      String oldName = currentVariable.getName();
      if (!oldName.equals(newName)) {
        context.runCommand(
            new SetVariableNameCmd(currentVariable, newName, SourceType.USER_DEFINED),
            "unable to rename variable");
        currentFunction =
            FunctionMutationSupport.refreshFunction(
                context, currentFunction, "local variable rename");
        currentVariable =
            FunctionVariableMutationSupport.requireLocalVariable(currentFunction, newName);
      }
    }

    if (newDataType != null) {
      DataType dt = FunctionMutationSupport.requireDataType(dataTypeResolver, newDataType);
      DataTypeReference oldType = GhidraDataTypeReferences.toReference(currentVariable.getDataType());
      DataTypeReference requestedType = GhidraDataTypeReferences.toReference(dt);
      if (!oldType.equals(requestedType)) {
        context.runCommand(
            new SetVariableDataTypeCmd(currentVariable, dt, SourceType.USER_DEFINED),
            "failed to set variable type");
        currentFunction =
            FunctionMutationSupport.refreshFunction(
                context, currentFunction, "local variable type update");
        currentVariable =
            FunctionVariableMutationSupport.requireLocalVariable(
                currentFunction, currentVariable.getName());
      }
    }
    return FunctionDescriptions.describeLocalVariable(currentVariable);
  }

  private static FunctionResource.LocalVariableResource patchDecompilerLocal(
      GhidraSession context,
      DecompilerPool decompilerPool,
      Function function,
      String variableName,
      String newName,
      DataTypeReference newDataType,
      FunctionMutations.ParameterDataTypeResolver dataTypeResolver) {
    HighFunction highFunction = decompilerPool.decompileHighFunction(function);
    List<HighSymbol> matches = DecompilerLocalSymbols.findByName(highFunction, variableName);
    if (matches.isEmpty()) {
      throw new NoSuchElementException("local variable not found: " + variableName);
    }
    if (matches.size() > 1) {
      throw new IllegalArgumentException("ambiguous local variable name: " + variableName);
    }

    HighSymbol symbol = matches.getFirst();
    String renameTarget = newName == null || newName.isBlank() ? null : newName;
    DataType resolvedDataType =
        newDataType == null
            ? null
            : FunctionMutationSupport.requireDataType(dataTypeResolver, newDataType);
    CommittedTarget target = committedTarget(function, symbol);

    try {
      HighFunctionDBUtil.updateDBVariable(
          symbol, renameTarget, resolvedDataType, SourceType.USER_DEFINED);
    } catch (DuplicateNameException error) {
      throw new TransactionExecutionException(
          "unable to rename variable: " + error.getMessage(), error);
    } catch (InvalidInputException error) {
      String prefix =
          resolvedDataType != null ? "failed to set variable type" : "unable to rename variable";
      throw new TransactionExecutionException(prefix + ": " + error.getMessage(), error);
    }

    Function refreshed =
        FunctionMutationSupport.refreshFunction(context, function, "local variable update");
    return resolveCommittedResource(refreshed, symbol, renameTarget, resolvedDataType, target);
  }

  private static CommittedTarget committedTarget(Function function, HighSymbol symbol) {
    VariableStorage storage = symbol.getStorage();
    Address pcAddress = symbol.getPCAddress();
    HighVariable highVariable = symbol.getHighVariable();
    if (storage != null
        && !storage.isHashStorage()
        && highVariable != null
        && highVariable.requiresDynamicStorage()
        && highVariable.getRepresentative() != null) {
      DynamicEntry entry = DynamicEntry.build(highVariable.getRepresentative());
      storage = entry.getStorage();
      pcAddress = entry.getPCAdress();
    }
    int firstUseOffset = 0;
    if (pcAddress != null && function.getEntryPoint() != null) {
      firstUseOffset = (int) pcAddress.subtract(function.getEntryPoint());
    }
    return new CommittedTarget(storage, firstUseOffset);
  }

  private static FunctionResource.LocalVariableResource resolveCommittedResource(
      Function function,
      HighSymbol symbol,
      String renameTarget,
      DataType resolvedDataType,
      CommittedTarget target) {
    if (renameTarget != null) {
      Optional<Variable> byRename =
          FunctionVariableMutationSupport.findLocalVariable(function, renameTarget);
      if (byRename.isPresent()) {
        return FunctionDescriptions.describeLocalVariable(byRename.get());
      }
    }

    VariableStorage storage = target.storage();
    if (storage != null && storage.isHashStorage() && storage.getFirstVarnode() != null) {
      long hashOffset = storage.getFirstVarnode().getOffset();
      for (Variable unique : function.getLocalVariables(VariableFilter.UNIQUE_VARIABLE_FILTER)) {
        if (unique.getFirstStorageVarnode() != null
            && unique.getFirstStorageVarnode().getOffset() == hashOffset) {
          return FunctionDescriptions.describeLocalVariable(unique);
        }
      }
    }

    if (storage != null) {
      Variable exactMatch = null;
      Variable intersectingMatch = null;
      int intersectingCount = 0;
      for (Variable candidate : function.getLocalVariables()) {
        if (candidate.getFirstUseOffset() != target.firstUseOffset()) continue;
        VariableStorage candidateStorage = candidate.getVariableStorage();
        if (candidateStorage == null) continue;
        if (candidateStorage.equals(storage)) {
          exactMatch = candidate;
          break;
        }
        if (candidateStorage.intersects(storage)) {
          intersectingMatch = candidate;
          intersectingCount++;
        }
      }
      if (exactMatch != null) {
        return FunctionDescriptions.describeLocalVariable(exactMatch);
      }
      if (intersectingCount == 1) {
        return FunctionDescriptions.describeLocalVariable(intersectingMatch);
      }
    }

    Optional<Variable> byOriginalName =
        FunctionVariableMutationSupport.findLocalVariable(function, symbol.getName());
    if (byOriginalName.isPresent()) {
      return FunctionDescriptions.describeLocalVariable(byOriginalName.get());
    }

    String effectiveName = renameTarget != null ? renameTarget : symbol.getName();
    DataType effectiveDataType =
        resolvedDataType != null
            ? resolvedDataType
            : (symbol.getDataType() == null ? DataType.DEFAULT : symbol.getDataType());
    VariableStorage effectiveStorage = storage != null ? storage : symbol.getStorage();
    return new FunctionResource.LocalVariableResource(
        effectiveName,
        GhidraDataTypeReferences.toReference(effectiveDataType),
        VariableStorageReference.serialization(effectiveStorage.getSerializationString()));
  }

  private record CommittedTarget(VariableStorage storage, int firstUseOffset) {}
}
