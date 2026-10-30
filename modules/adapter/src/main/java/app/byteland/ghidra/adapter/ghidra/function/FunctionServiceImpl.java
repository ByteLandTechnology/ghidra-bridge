package app.byteland.ghidra.adapter.ghidra.function;

import app.byteland.ghidra.adapter.ghidra.GhidraDataTypeReferences;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.function.FunctionCallResource;
import app.byteland.ghidra.service.function.FunctionResource;
import app.byteland.ghidra.service.function.FunctionService;
import app.byteland.ghidra.service.function.VariableStorageReference;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.cmd.function.DeleteFunctionCmd;
import ghidra.program.database.function.OverlappingFunctionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.InvalidInputException;
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

  @Override
  public FunctionResource createFunction(String rawAddress, String name, boolean disassemble) {
    Address entry = context.parseAddress(rawAddress);
    Program program = context.currentProgram();
    FunctionManager manager = program.getFunctionManager();
    Function existing = manager.getFunctionContaining(entry);
    if (existing != null) {
      throw new IllegalArgumentException("address is already in a function: " + rawAddress);
    }
    if (program.getListing().getInstructionAt(entry) == null) {
      if (!disassemble || !context.script().disassemble(entry)) {
        throw new IllegalArgumentException("no instruction at function entry: " + rawAddress);
      }
    }
    AddressSetView body =
        CreateFunctionCmd.getFunctionBody(program, entry, false, context.script().getMonitor());
    if (context.script().getMonitor().isCancelled()) {
      throw new IllegalArgumentException("function creation was cancelled");
    }
    if (manager.getFunctionsOverlapping(body).hasNext()) {
      throw new IllegalArgumentException("function body overlaps another function: " + rawAddress);
    }
    String functionName = name;
    SourceType source = name == null ? SourceType.DEFAULT : SourceType.USER_DEFINED;
    Namespace namespace = program.getGlobalNamespace();
    Symbol symbol = program.getSymbolTable().getPrimarySymbol(entry);
    if (name == null && symbol != null && symbol.getSource() != SourceType.DEFAULT) {
      functionName = symbol.getName();
      source = symbol.getSource();
      Namespace parent = symbol.getParentNamespace();
      if (parent.getSymbol().getSymbolType() != SymbolType.FUNCTION) namespace = parent;
    }
    Function function;
    try {
      function = manager.createFunction(functionName, namespace, entry, body, source);
    } catch (InvalidInputException | OverlappingFunctionException error) {
      throw new IllegalArgumentException("unable to create function: " + error.getMessage(), error);
    }
    if (function == null) {
      throw new IllegalArgumentException("function was not created at: " + rawAddress);
    }
    if (name != null && !name.equals(function.getName())) {
      throw new IllegalArgumentException("function name was not applied: " + name);
    }
    return FunctionDescriptions.describe(function, Set.of());
  }

  @Override
  public void deleteFunction(String rawAddress) {
    Function function = lookupQueries.resolveFunction(rawAddress);
    Address entry = function.getEntryPoint();
    context.runCommand(new DeleteFunctionCmd(entry, false), "unable to delete function");
    if (context.script().getFunctionAt(entry) != null) {
      throw new IllegalArgumentException("function was not deleted at: " + rawAddress);
    }
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
