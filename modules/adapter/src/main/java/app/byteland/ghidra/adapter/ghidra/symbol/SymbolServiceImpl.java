package app.byteland.ghidra.adapter.ghidra.symbol;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.symbol.SymbolResource;
import app.byteland.ghidra.service.symbol.SymbolService;
import java.util.Set;

public final class SymbolServiceImpl implements SymbolService {
  private final GhidraSession context;

  public SymbolServiceImpl(GhidraSession context) {
    this.context = context;
  }

  @Override
  public Page<SymbolResource> listSymbols(SymbolQuery query) {
    return SymbolQueries.listSymbols(context, query);
  }

  @Override
  public Page<SymbolResource> listSymbols(SymbolQuery query, Set<String> fields) {
    return SymbolQueries.listSymbols(
        context,
        fields == null
            ? query
            : new SymbolQuery(
                query.scan(),
                query.name(),
                query.address(),
                query.type(),
                query.namespace(),
                query.sourceType(),
                query.caseSensitive(),
                query.limit(),
                query.cursor(),
                fields));
  }

  @Override
  public SymbolResource getSymbol(long symbolId) {
    return getSymbol(symbolId, null);
  }

  @Override
  public SymbolResource getSymbol(long symbolId, Set<String> fields) {
    return SymbolDescriptions.describe(SymbolQueries.getSymbolById(context, symbolId), fields);
  }


  @Override
  public void renameSymbol(long symbolId, String newName) {
    SymbolMutations.renameSymbol(context, SymbolQueries.getSymbolById(context, symbolId), newName);
  }

  @Override
  public DemangleResult demangleSymbols() {
    return SymbolDemangling.apply(context);
  }
}
