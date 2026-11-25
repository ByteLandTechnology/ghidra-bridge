package app.byteland.ghidra.adapter.ghidra.symbol;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.CppSymbolNames;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.symbol.SymbolResource;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;

public final class SymbolDescriptions {
  private SymbolDescriptions() {}

  public static SymbolResource describe(Symbol symbol) {
    return describe(null, symbol);
  }

  public static SymbolResource describe(GhidraSession context, Symbol symbol) {
    String idText = String.valueOf(symbol.getID());
    String name = symbol.getName();
    Address address = symbol.getAddress();
    Program program =
        CppSymbolNames.isMangled(name)
            ? (context != null ? context.currentProgramOrNull() : symbol.getProgram())
            : null;
    return describe(
        context, program, symbol, idText, name, address, AddressUtil.canonicalAddress(address));
  }

  static SymbolResource describe(
      GhidraSession context,
      Program program,
      Symbol symbol,
      String idText,
      String name,
      Address address,
      String canonicalAddress) {
    Namespace parent = symbol.getParentNamespace();
    String demangled =
        CppSymbolNames.isMangled(name)
            ? CppSymbolNames.demangled(
                context, program != null ? program : symbol.getProgram(), name, address)
            : null;
    return new SymbolResource(
        idText,
        name,
        canonicalAddress,
        parent == null ? null : parent.getName(true),
        symbol.getSymbolType().toString(),
        String.valueOf(symbol.getSource()),
        symbol.isPrimary(),
        demangled);
  }
}
