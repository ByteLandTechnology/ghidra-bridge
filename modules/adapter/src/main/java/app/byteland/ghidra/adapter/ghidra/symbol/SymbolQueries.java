package app.byteland.ghidra.adapter.ghidra.symbol;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.symbol.SymbolResource;
import app.byteland.ghidra.service.symbol.SymbolService.SymbolQuery;
import ghidra.program.model.symbol.Symbol;
import java.util.NoSuchElementException;

final class SymbolQueries {
  private SymbolQueries() {}

  static Page<SymbolResource> listSymbols(GhidraSession context, SymbolQuery query) {
    return new SymbolListQueries(context).listSymbols(query);
  }

  static Symbol getSymbolById(GhidraSession context, long symbolId) {
    Symbol symbol = context.currentProgram().getSymbolTable().getSymbol(symbolId);
    if (symbol == null) throw new NoSuchElementException("symbol not found: " + symbolId);
    return symbol;
  }
}
