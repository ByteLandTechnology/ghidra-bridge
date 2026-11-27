package app.byteland.ghidra.adapter.ghidra.function;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.CppSymbolNames;
import app.byteland.ghidra.adapter.ghidra.FieldProjections;
import app.byteland.ghidra.adapter.ghidra.GhidraDataTypeReferences;
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
    return describe(function, includes, null);
  }

  static FunctionResource describe(Function function, Set<String> includes, Set<String> fields) {
    boolean needEntry = FieldProjections.allows(fields, "entry");
    boolean needName = FieldProjections.allows(fields, "name");
    boolean needDemangled = FieldProjections.allows(fields, "demangled_name");
    Address entryPoint = needEntry || needDemangled ? function.getEntryPoint() : null;
    String name = needName || needDemangled ? function.getName() : null;
    Integer stackPurgeSize = null;
    if (FieldProjections.allows(fields, "stack_purge_size")) {
      int rawPurgeSize = function.getStackPurgeSize();
      stackPurgeSize = rawPurgeSize < 0 ? null : rawPurgeSize;
    }
    return new FunctionResource(
        needEntry ? AddressUtil.canonicalAddress(entryPoint) : null,
        needName ? name : null,
        FieldProjections.allows(fields, "namespace")
            ? String.valueOf(function.getParentNamespace())
            : null,
        FieldProjections.allows(fields, "body") ? describeBody(function, fields) : null,
        FieldProjections.allows(fields, "signature")
            ? String.valueOf(function.getSignature())
            : null,
        FieldProjections.allows(fields, "return_type")
            ? GhidraDataTypeReferences.toReference(function.getReturnType())
            : null,
        FieldProjections.allows(fields, "return_storage")
            ? describeStorage(function.getReturn().getVariableStorage())
            : null,
        FieldProjections.allows(fields, "parameter_count") ? function.getParameterCount() : 0,
        FieldProjections.allows(fields, "calling_convention")
            ? String.valueOf(function.getCallingConventionName())
            : null,
        includes.contains("parameters") && FieldProjections.allows(fields, "parameters")
            ? describeParameters(function, fields)
            : null,
        includes.contains("locals") && FieldProjections.allows(fields, "local_variables")
            ? describeLocalVariables(function, fields)
            : null,
        FieldProjections.allows(fields, "comment") ? function.getComment() : null,
        FieldProjections.allows(fields, "is_inline") && function.isInline(),
        FieldProjections.allows(fields, "has_no_return") && function.hasNoReturn(),
        FieldProjections.allows(fields, "has_var_args") && function.hasVarArgs(),
        FieldProjections.allows(fields, "has_custom_variable_storage")
            && function.hasCustomVariableStorage(),
        stackPurgeSize,
        FieldProjections.allows(fields, "external") && function.isExternal(),
        FieldProjections.allows(fields, "thunk") && function.isThunk(),
        FieldProjections.allows(fields, "repeatable_comment")
            ? function.getRepeatableComment()
            : null,
        FieldProjections.allows(fields, "tags") ? describeTags(function) : null,
        needDemangled
            ? CppSymbolNames.demangled(function.getProgram(), name, entryPoint)
            : null);
  }

  private static FunctionResource.Body describeBody(Function function, Set<String> fields) {
    AddressSetView body = function.getBody();
    if (body.isEmpty()) return null;
    return new FunctionResource.Body(
        FieldProjections.allowsSubfield(fields, "body", "start")
            ? AddressUtil.canonicalAddress(body.getMinAddress())
            : null,
        FieldProjections.allowsSubfield(fields, "body", "end")
            ? AddressUtil.canonicalAddress(body.getMaxAddress())
            : null,
        FieldProjections.allowsSubfield(fields, "body", "num_addresses")
            ? body.getNumAddresses()
            : 0L);
  }

  static List<FunctionResource.ParameterResource> describeParameters(Function function) {
    return describeParameters(function, null);
  }

  static List<FunctionResource.ParameterResource> describeParameters(
      Function function, Set<String> fields) {
    List<FunctionResource.ParameterResource> items = new ArrayList<>();
    for (Parameter parameter : function.getParameters()) {
      items.add(describeParameter(parameter, fields));
    }
    return List.copyOf(items);
  }

  static FunctionResource.ParameterResource describeParameter(Parameter parameter) {
    return describeParameter(parameter, null);
  }

  static FunctionResource.ParameterResource describeParameter(
      Parameter parameter, Set<String> fields) {
    return new FunctionResource.ParameterResource(
        FieldProjections.allowsSubfield(fields, "parameters", "ordinal")
            ? parameter.getOrdinal()
            : 0,
        FieldProjections.allowsSubfield(fields, "parameters", "name") ? parameter.getName() : null,
        FieldProjections.allowsSubfield(fields, "parameters", "data_type")
            ? GhidraDataTypeReferences.toReference(parameter.getFormalDataType())
            : null,
        FieldProjections.allowsSubfield(fields, "parameters", "storage")
            ? describeStorage(parameter.getVariableStorage())
            : null);
  }

  static List<FunctionResource.LocalVariableResource> describeLocalVariables(Function function) {
    return describeLocalVariables(function, null);
  }

  static List<FunctionResource.LocalVariableResource> describeLocalVariables(
      Function function, Set<String> fields) {
    List<FunctionResource.LocalVariableResource> items = new ArrayList<>();
    for (Variable variable : function.getLocalVariables()) {
      items.add(
          new FunctionResource.LocalVariableResource(
              FieldProjections.allowsSubfield(fields, "local_variables", "name")
                  ? variable.getName()
                  : null,
              FieldProjections.allowsSubfield(fields, "local_variables", "data_type")
                  ? GhidraDataTypeReferences.toReference(variable.getDataType())
                  : null,
              FieldProjections.allowsSubfield(fields, "local_variables", "storage")
                  ? describeStorage(variable.getVariableStorage())
                  : null));
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
