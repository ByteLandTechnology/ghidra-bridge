package app.byteland.ghidra.adapter.ghidra.function;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.CppSymbolNames;
import app.byteland.ghidra.adapter.ghidra.GhidraDataTypeReferences;
import app.byteland.ghidra.service.function.FunctionResource;
import app.byteland.ghidra.service.function.VariableStorageReference;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.DynamicEntry;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.LocalSymbolMap;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Converts Ghidra {@link Function} and {@link HighFunction} state into domain resources. */
public final class FunctionDescriptions {
  private FunctionDescriptions() {}

  static FunctionResource describe(Function function, Set<String> includes) {
    return describe(function, includes, null);
  }

  static FunctionResource describe(
      Function function, Set<String> includes, HighFunction highFunction) {
    AddressSetView body = function.getBody();
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
        function.getParameterCount(),
        String.valueOf(function.getCallingConventionName()),
        includes.contains("parameters") ? describeParameters(function) : null,
        includes.contains("locals") ? describeLocalVariables(function, highFunction) : null,
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
    List<FunctionResource.ParameterResource> items = new ArrayList<>();
    for (Parameter parameter : function.getParameters()) items.add(describeParameter(parameter));
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

  /** Merges committed Function DB locals with uncommitted non-parameter {@link HighSymbol}s. */
  public static List<FunctionResource.LocalVariableResource> describeLocalVariables(
      Function function, HighFunction highFunction) {
    List<FunctionResource.LocalVariableResource> items = new ArrayList<>();
    Map<String, HighSymbol> highByName = new HashMap<>();
    List<HighSymbol> extraHighSymbols = new ArrayList<>();
    if (highFunction != null && highFunction.getLocalSymbolMap() != null) {
      LocalSymbolMap symbolMap = highFunction.getLocalSymbolMap();
      Iterator<HighSymbol> iterator = symbolMap.getSymbols();
      while (iterator.hasNext()) {
        HighSymbol symbol = iterator.next();
        if (symbol == null || symbol.isParameter() || symbol.isGlobal()) {
          continue;
        }
        String name = symbol.getName();
        if (name == null || name.isBlank()) {
          continue;
        }
        highByName.putIfAbsent(name, symbol);
        if (symbol.getSymbol() == null && HighFunctionDBUtil.getFunctionVariable(symbol) == null) {
          extraHighSymbols.add(symbol);
        }
      }
    }

    Set<String> seenNames = new HashSet<>();
    Set<String> seenKeys = new HashSet<>();
    for (Variable variable : function.getLocalVariables()) {
      String name = variable.getName();
      VariableStorage storage = variable.getVariableStorage();
      DataType dataType = variable.getDataType();
      HighSymbol mapped = highByName.get(name);
      if (mapped != null
          && Undefined.isUndefined(dataType)
          && !mapped.isTypeLocked()
          && mapped.getDataType() != null) {
        dataType = mapped.getDataType();
      }
      String serialization = storage.getSerializationString();
      seenNames.add(name);
      seenKeys.add(serialization + "\0" + name);
      items.add(
          new FunctionResource.LocalVariableResource(
              name,
              GhidraDataTypeReferences.toReference(dataType),
              describeStorage(storage)));
    }

    for (HighSymbol symbol : extraHighSymbols) {
      String name = symbol.getName();
      VariableStorage storage = effectiveStorage(symbol);
      if (storage == null || storage.isBadStorage() || storage.isUnassignedStorage()) {
        continue;
      }
      DataType dataType = symbol.getDataType();
      if (dataType == null) {
        continue;
      }
      String serialization = storage.getSerializationString();
      String key = serialization + "\0" + name;
      if (seenNames.contains(name) || !seenKeys.add(key)) {
        continue;
      }
      items.add(
          new FunctionResource.LocalVariableResource(
              name,
              GhidraDataTypeReferences.toReference(dataType),
              describeStorage(storage)));
    }
    return List.copyOf(items);
  }

  /** Returns the canonical {@link VariableStorage} used by Ghidra for {@code symbol}. */
  public static VariableStorage effectiveStorage(HighSymbol symbol) {
    if (symbol == null || symbol.getFirstWholeMap() == null) {
      return null;
    }
    VariableStorage storage = symbol.getStorage();
    if (storage == null) {
      return null;
    }
    HighVariable highVariable = symbol.getHighVariable();
    if (!storage.isHashStorage()
        && highVariable != null
        && highVariable.requiresDynamicStorage()
        && highVariable.getRepresentative() != null) {
      return DynamicEntry.build(highVariable.getRepresentative()).getStorage();
    }
    return storage;
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
