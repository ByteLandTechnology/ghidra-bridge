package app.byteland.ghidra.adapter.ghidra.function;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.CppSymbolNames;
import app.byteland.ghidra.adapter.ghidra.GhidraDataTypeReferences;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.function.FunctionResource;
import app.byteland.ghidra.service.function.VariableStorageReference;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

final class FunctionDescriptions {
  private FunctionDescriptions() {}

  static FunctionResource describe(Function function, Set<String> includes) {
    return describe(null, function, includes);
  }

  static FunctionResource describe(GhidraSession context, Function function, Set<String> includes) {
    Address entryPoint = function.getEntryPoint();
    return describe(
        context,
        function,
        entryPoint,
        AddressUtil.canonicalAddress(entryPoint),
        function.getName(),
        includes);
  }

  static FunctionResource describe(
      GhidraSession context,
      Function function,
      Address entryPoint,
      String canonicalEntry,
      String name,
      Set<String> includes) {
    AddressSetView body = function.getBody();
    int stackPurgeSize = function.getStackPurgeSize();
    String demangled =
        CppSymbolNames.isMangled(name)
            ? CppSymbolNames.demangled(context, function.getProgram(), name, entryPoint)
            : null;
    return new FunctionResource(
        canonicalEntry,
        name,
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
        includes.contains("locals") ? describeLocalVariables(function) : null,
        function.getComment(),
        function.isInline(),
        function.hasNoReturn(),
        function.hasVarArgs(),
        function.hasCustomVariableStorage(),
        stackPurgeSize < 0 ? null : stackPurgeSize,
        function.isExternal(),
        function.isThunk(),
        function.getRepeatableComment(),
        describeTags(function),
        demangled);
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
    List<FunctionResource.LocalVariableResource> items = new ArrayList<>();
    for (Variable variable : function.getLocalVariables()) {
      items.add(
          new FunctionResource.LocalVariableResource(
              variable.getName(),
              GhidraDataTypeReferences.toReference(variable.getDataType()),
              describeStorage(variable.getVariableStorage())));
    }
    return List.copyOf(items);
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
