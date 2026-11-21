package app.byteland.ghidra.adapter.ghidra.symbol;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.CppSymbolNames;
import app.byteland.ghidra.service.symbol.SymbolResource;
import ghidra.program.model.symbol.Symbol;

/**
 * Maps Ghidra {@link Symbol} instances to domain {@link SymbolResource} records.
 */
public final class SymbolDescriptions {
  private SymbolDescriptions() {}

  /**
   * Converts a Ghidra {@link Symbol} into a {@link SymbolResource}.
   *
   * @param symbol Ghidra symbol
   * @return domain symbol resource
   */
  public static SymbolResource describe(Symbol symbol) {
    return new SymbolResource(
        String.valueOf(symbol.getID()),
        symbol.getName(),
        AddressUtil.canonicalAddress(symbol.getAddress()),
        symbol.getParentNamespace() == null ? null : symbol.getParentNamespace().getName(true),
        symbol.getSymbolType().toString(),
        String.valueOf(symbol.getSource()),
        symbol.isPrimary(),
        CppSymbolNames.demangled(symbol.getProgram(), symbol.getName(), symbol.getAddress()));
  }
}
