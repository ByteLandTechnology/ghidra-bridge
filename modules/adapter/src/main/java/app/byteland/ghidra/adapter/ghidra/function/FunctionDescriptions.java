package app.byteland.ghidra.adapter.ghidra.function;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.CppSymbolNames;
import app.byteland.ghidra.adapter.ghidra.GhidraDataTypeReferences;
import app.byteland.ghidra.service.function.FunctionResource;
import app.byteland.ghidra.service.function.VariableStorageReference;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.EquateSymbol;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

final class FunctionDescriptions {
  private FunctionDescriptions() {}

  static FunctionResource describe(Function function, Set<String> includes) {
    return describe(function, includes, null);
  }

  static FunctionResource describe(
      Function function, Set<String> includes, HighFunction highFunction) {
    AddressSetView body = function.getBody();
    List<FunctionResource.ParameterResource> parameters =
        includes.contains("parameters") ? describeParameters(function, highFunction) : null;
    List<FunctionResource.LocalVariableResource> localVariables =
        includes.contains("locals") ? describeLocalVariables(function, highFunction) : null;
    int parameterCount =
        parameters != null
            ? Math.max(function.getParameterCount(), parameters.size())
            : function.getParameterCount();
    return new FunctionResource(
        AddressUtil.canonicalAddress(function.getEntryPoint()),
        function.getName(),
        String.valueOf(function.getParentNamespace()),
        body.isEmpty()
            ? null
            : new FunctionResource.Body(
                AddressUtil.canonicalAddress(body.getMinAddress()),
                AddressUtil.canonicalAddress(body.getMaxAddress()),
                body.getNumAddresses()),
        String.valueOf(function.getSignature()),
        GhidraDataTypeReferences.toReference(function.getReturnType()),
        describeStorage(function.getReturn().getVariableStorage()),
        parameterCount,
        String.valueOf(function.getCallingConventionName()),
        parameters,
        localVariables,
        function.getComment(),
        function.isInline(),
        function.hasNoReturn(),
        function.hasVarArgs(),
        function.hasCustomVariableStorage(),
        function.getStackPurgeSize() < 0 ? null : function.getStackPurgeSize(),
        function.isExternal(),
        function.isThunk(),
        function.getRepeatableComment(),
        describeTags(function),
        CppSymbolNames.demangled(
            function.getProgram(), function.getName(), function.getEntryPoint()));
  }

  static List<FunctionResource.ParameterResource> describeParameters(Function function) {
    return describeParameters(function, null);
  }

  static List<FunctionResource.ParameterResource> describeParameters(
      Function function, HighFunction highFunction) {
    List<FunctionResource.ParameterResource> items = new ArrayList<>();
    Set<Integer> seenOrdinals = new HashSet<>();
    Set<String> seenNames = new HashSet<>();
    Set<String> seenStorages = new HashSet<>();
    for (Parameter parameter : function.getParameters()) {
      items.add(describeParameter(parameter));
      seenOrdinals.add(parameter.getOrdinal());
      if (parameter.getName() != null) {
        seenNames.add(parameter.getName());
      }
      recordStorage(seenStorages, parameter.getVariableStorage());
    }
    LocalSymbolMap symbolMap = highFunction == null ? null : highFunction.getLocalSymbolMap();
    if (symbolMap != null) {
      int count = symbolMap.getNumParams();
      for (int ordinal = 0; ordinal < count; ordinal++) {
        HighSymbol symbol = symbolMap.getParamSymbol(ordinal);
        if (symbol == null || symbol.isGlobal() || symbol.isHiddenReturn()) {
          continue;
        }
        String name = symbol.getName();
        VariableStorage storage = symbol.getStorage();
        if (name == null || name.isBlank() || storage == null || storage.isBadStorage()) {
          continue;
        }
        String serialization = storage.getSerializationString();
        if (serialization == null
            || serialization.isBlank()
            || seenOrdinals.contains(ordinal)
            || seenNames.contains(name)
            || seenStorages.contains(serialization)) {
          continue;
        }
        seenOrdinals.add(ordinal);
        seenNames.add(name);
        seenStorages.add(serialization);
        items.add(
            new FunctionResource.ParameterResource(
                ordinal,
                name,
                GhidraDataTypeReferences.toReference(symbol.getDataType()),
                VariableStorageReference.serialization(serialization)));
      }
    }
    return List.copyOf(items);
  }

  static FunctionResource.ParameterResource describeParameter(Parameter parameter) {
    return new FunctionResource.ParameterResource(
        parameter.getOrdinal(),
        parameter.getName(),
        GhidraDataTypeReferences.toReference(parameter.getFormalDataType()),
        describeStorage(parameter.getVariableStorage()));
  }

  static List<FunctionResource.LocalVariableResource> describeLocalVariables(Function function) {
    return describeLocalVariables(function, null);
  }

  static List<FunctionResource.LocalVariableResource> describeLocalVariables(
      Function function, HighFunction highFunction) {
    List<FunctionResource.LocalVariableResource> items = new ArrayList<>();
    Set<String> seenNames = new HashSet<>();
    Set<String> seenStorages = new HashSet<>();
    for (Parameter parameter : function.getParameters()) {
      if (parameter.getName() != null) {
        seenNames.add(parameter.getName());
      }
      recordStorage(seenStorages, parameter.getVariableStorage());
    }
    for (Variable variable : function.getLocalVariables()) {
      if (variable.getName() != null) {
        seenNames.add(variable.getName());
      }
      recordStorage(seenStorages, variable.getVariableStorage());
      items.add(
          new FunctionResource.LocalVariableResource(
              variable.getName(),
              GhidraDataTypeReferences.toReference(variable.getDataType()),
              describeStorage(variable.getVariableStorage())));
    }
    LocalSymbolMap symbolMap = highFunction == null ? null : highFunction.getLocalSymbolMap();
    if (symbolMap != null) {
      List<FunctionResource.LocalVariableResource> uncommitted = new ArrayList<>();
      Iterator<HighSymbol> symbols = symbolMap.getSymbols();
      while (symbols != null && symbols.hasNext()) {
        HighSymbol symbol = symbols.next();
        if (symbol == null
            || symbol instanceof EquateSymbol
            || symbol.isParameter()
            || symbol.isGlobal()
            || symbol.isThisPointer()
            || symbol.isHiddenReturn()) {
          continue;
        }
        String name = symbol.getName();
        VariableStorage storage = symbol.getStorage();
        if (name == null
            || name.isBlank()
            || storage == null
            || storage.isBadStorage()
            || storage.isUnassignedStorage()) {
          continue;
        }
        String serialization = storage.getSerializationString();
        if (serialization == null
            || serialization.isBlank()
            || seenNames.contains(name)
            || seenStorages.contains(serialization)) {
          continue;
        }
        seenNames.add(name);
        seenStorages.add(serialization);
        uncommitted.add(
            new FunctionResource.LocalVariableResource(
                name,
                GhidraDataTypeReferences.toReference(symbol.getDataType()),
                VariableStorageReference.serialization(serialization)));
      }
      uncommitted.sort(
          Comparator.comparing(FunctionResource.LocalVariableResource::name)
              .thenComparing(variable -> String.valueOf(variable.storage())));
      items.addAll(uncommitted);
    }
    return List.copyOf(items);
  }

  private static void recordStorage(Set<String> seenStorages, VariableStorage storage) {
    if (storage == null) return;
    String serialization = storage.getSerializationString();
    if (serialization != null && !serialization.isBlank()) {
      seenStorages.add(serialization);
    }
  }

  private static VariableStorageReference describeStorage(VariableStorage storage) {
    return VariableStorageReference.serialization(storage.getSerializationString());
  }

  private static List<String> describeTags(Function function) {
    List<String> tags = new ArrayList<>();
    for (Object tag : function.getTags()) tags.add(String.valueOf(tag));
    return List.copyOf(tags);
  }
}
