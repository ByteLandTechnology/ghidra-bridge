package app.byteland.ghidra.adapter.ghidra.symbol;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.service.symbol.SymbolResource;
import ghidra.program.model.symbol.Symbol;

final class SymbolDescriptions {
  private SymbolDescriptions() {}

  static SymbolResource describe(Symbol symbol) {
    return new SymbolResource(
        String.valueOf(symbol.getID()),
        symbol.getName(),
        AddressUtil.canonicalAddress(symbol.getAddress()),
        symbol.getParentNamespace() == null ? null : symbol.getParentNamespace().getName(),
        symbol.getSymbolType().toString(),
        String.valueOf(symbol.getSource()),
        symbol.isPrimary());
  }
}
