package app.byteland.ghidra.adapter.ghidra.symbol;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.CppSymbolNames;
import app.byteland.ghidra.adapter.ghidra.FieldProjections;
import app.byteland.ghidra.service.symbol.SymbolResource;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import java.util.Set;

public final class SymbolDescriptions {
  private SymbolDescriptions() {}

  public static SymbolResource describe(Symbol symbol) {
    return describe(symbol, null);
  }

  public static SymbolResource describe(Symbol symbol, Set<String> fields) {
    boolean needName = FieldProjections.allows(fields, "name");
    boolean needAddress = FieldProjections.allows(fields, "address");
    boolean needDemangled = FieldProjections.allows(fields, "demangled_name");
    String name = needName || needDemangled ? symbol.getName() : null;
    Address address = needAddress || needDemangled ? symbol.getAddress() : null;
    String namespace = null;
    if (FieldProjections.allows(fields, "namespace")) {
      Namespace parent = symbol.getParentNamespace();
      namespace = parent == null ? null : parent.getName(true);
    }
    return new SymbolResource(
        FieldProjections.allows(fields, "id") ? String.valueOf(symbol.getID()) : null,
        needName ? name : null,
        needAddress ? AddressUtil.canonicalAddress(address) : null,
        namespace,
        FieldProjections.allows(fields, "type") ? symbol.getSymbolType().toString() : null,
        FieldProjections.allows(fields, "source_type")
            ? String.valueOf(symbol.getSource())
            : null,
        FieldProjections.allows(fields, "primary") && symbol.isPrimary(),
        needDemangled ? CppSymbolNames.demangled(symbol.getProgram(), name, address) : null);
  }
}
