package app.byteland.ghidra.adapter.ghidra.function;

import app.byteland.ghidra.adapter.ghidra.GhidraDataTypeReferences;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.function.FunctionCallResource;
import app.byteland.ghidra.service.function.FunctionResource;
import app.byteland.ghidra.service.function.FunctionService;
import app.byteland.ghidra.service.function.VariableStorageReference;
import java.util.Set;

public final class FunctionServiceImpl implements FunctionService {
  private final GhidraSession context;
  private final FunctionLookupQueries lookupQueries;
  private final FunctionListQueries listQueries;
  private final FunctionRelationQueries relationQueries;
  private final FunctionMutations.ParameterDataTypeResolver dataTypeResolver;

  public FunctionServiceImpl(GhidraSession context) {
    this.context = context;
    this.lookupQueries = new FunctionLookupQueries(context);
    this.listQueries = new FunctionListQueries(context, lookupQueries);
    this.relationQueries = new FunctionRelationQueries(lookupQueries);
    this.dataTypeResolver =
        input ->
            GhidraDataTypeReferences.resolve(context.currentProgram().getDataTypeManager(), input);
  }

  @Override
  public Page<FunctionResource> listFunctions(FunctionQuery query) {
    return listQueries.listFunctions(query);
  }

  @Override
  public FunctionResource getFunction(String rawAddress, Set<String> includes) {
    return FunctionDescriptions.describe(
        lookupQueries.resolveFunction(rawAddress), FunctionIncludes.normalize(includes));
  }

  static FunctionResource toFunctionSummary(
      ghidra.program.model.listing.Function function, Set<String> includes) {
    return FunctionDescriptions.describe(function, FunctionIncludes.normalize(includes));
  }

  @Override
  public void patchFunction(
      String rawAddress,
      String newName,
      String newComment,
      boolean commentPresent,
      DataTypeReference returnType,
      VariableStorageReference returnStorage,
      String callingConvention,
      FunctionAttributePatch attributes) {
    FunctionMutations.patchFunction(
        context,
        lookupQueries.resolveFunction(rawAddress),
        newName,
        newComment,
        commentPresent,
        returnType,
        returnStorage,
        callingConvention,
        attributes,
        dataTypeResolver);
  }

  @Override
  public Page<FunctionCallResource> getCallers(String rawAddress, int limit, String cursor) {
    return relationQueries.getCallers(rawAddress, limit, cursor);
  }

  @Override
  public Page<FunctionCallResource> getCallees(String rawAddress, int limit, String cursor) {
    return relationQueries.getCallees(rawAddress, limit, cursor);
  }

  @Override
  public void patchParameter(
      String rawAddress,
      int ordinal,
      String newName,
      DataTypeReference newDataType,
      VariableStorageReference storage) {
    FunctionParameterMutations.patchParameter(
        context,
        lookupQueries.resolveFunction(rawAddress),
        ordinal,
        newName,
        newDataType,
        storage,
        dataTypeResolver);
  }

  @Override
  public void addParameter(
      String rawAddress,
      int ordinal,
      String parameterName,
      DataTypeReference dataType,
      VariableStorageReference storage) {
    FunctionParameterMutations.addParameter(
        context,
        lookupQueries.resolveFunction(rawAddress),
        ordinal,
        parameterName,
        dataType,
        storage,
        dataTypeResolver);
  }

  @Override
  public void removeParameter(String rawAddress, int ordinal) {
    FunctionParameterMutations.removeParameter(
        context, lookupQueries.resolveFunction(rawAddress), ordinal);
  }

  @Override
  public void patchLocalVariable(
      String rawAddress, String variableName, String newName, DataTypeReference newDataType) {
    FunctionLocalVariableMutations.patchLocalVariable(
        context,
        lookupQueries.resolveFunction(rawAddress),
        variableName,
        newName,
        newDataType,
        dataTypeResolver);
  }
}
