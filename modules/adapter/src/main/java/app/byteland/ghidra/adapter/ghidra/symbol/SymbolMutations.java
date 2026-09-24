package app.byteland.ghidra.adapter.ghidra.symbol;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.ScriptSymbolRenamer;
import ghidra.program.model.symbol.Symbol;

final class SymbolMutations {
  private SymbolMutations() {}

  static void renameSymbol(GhidraSession context, Symbol symbol, String newName) {
    ScriptSymbolRenamer.rename(context, symbol, newName);
  }
}
