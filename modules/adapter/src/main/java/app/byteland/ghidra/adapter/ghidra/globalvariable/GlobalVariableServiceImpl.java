package app.byteland.ghidra.adapter.ghidra.globalvariable;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.globalvariable.GlobalVariableResource;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService;
import java.util.Set;

public final class GlobalVariableServiceImpl implements GlobalVariableService {
  private final GhidraSession context;
  private final GlobalVariableQueries queries;
  private final GlobalVariableMutations mutations;

  public GlobalVariableServiceImpl(GhidraSession context) {
    this.context = context;
    this.queries = new GlobalVariableQueries(context);
    this.mutations = new GlobalVariableMutations(context);
  }

  @Override
  public GlobalVariableResource getGlobalVariable(String address) {
    return getGlobalVariable(address, null);
  }

  @Override
  public GlobalVariableResource getGlobalVariable(String address, Set<String> fields) {
    return queries.getGlobalVariable(address, fields);
  }

  @Override
  public Page<GlobalVariableResource> listGlobalVariables(Query query) {
    return queries.listGlobalVariables(query);
  }

  @Override
  public Page<GlobalVariableResource> listGlobalVariables(Query query, Set<String> fields) {
    return queries.listGlobalVariables(
        fields == null
            ? query
            : new Query(
                query.scan(),
                query.name(),
                query.namespace(),
                query.caseSensitive(),
                query.limit(),
                query.cursor(),
                fields));
  }

  @Override
  public void writeGlobalVariable(Mutation mutation, WriteMode mode) {
    context.withTransaction(
        () -> {
          mutations.writeGlobalVariable(mutation, mode);
          return null;
        });
  }

  @Override
  public void deleteGlobalVariable(String address, boolean deleteSymbol) {
    context.withTransaction(
        () -> {
          mutations.deleteGlobalVariable(address, deleteSymbol);
          return null;
        });
  }
}
