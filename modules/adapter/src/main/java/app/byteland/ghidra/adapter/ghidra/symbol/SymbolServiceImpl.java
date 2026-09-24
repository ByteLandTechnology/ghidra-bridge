package app.byteland.ghidra.adapter.ghidra.symbol;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.symbol.SymbolResource;
import app.byteland.ghidra.service.symbol.SymbolService;

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
  public SymbolResource getSymbol(long symbolId) {
    return SymbolDescriptions.describe(SymbolQueries.getSymbolById(context, symbolId));
  }


  @Override
  public void renameSymbol(long symbolId, String newName) {
    SymbolMutations.renameSymbol(context, SymbolQueries.getSymbolById(context, symbolId), newName);
  }
}
