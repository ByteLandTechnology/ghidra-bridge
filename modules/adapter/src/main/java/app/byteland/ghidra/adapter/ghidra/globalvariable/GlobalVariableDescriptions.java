package app.byteland.ghidra.adapter.ghidra.globalvariable;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraDataTypeReferences;
import app.byteland.ghidra.service.globalvariable.GlobalVariableResource;
import ghidra.program.model.listing.Data;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;

final class GlobalVariableDescriptions {
  private GlobalVariableDescriptions() {}

  static GlobalVariableResource describe(Data data, Symbol primarySymbol) {
    Namespace namespace = primarySymbol == null ? null : primarySymbol.getParentNamespace();
    return new GlobalVariableResource(
        AddressUtil.canonicalAddress(data.getAddress()),
        primarySymbol == null ? null : primarySymbol.getName(),
        namespace == null ? null : namespace.getName(),
        GhidraDataTypeReferences.toReference(data.getDataType()),
        data.getLength(),
        String.valueOf(data.getValue()),
        representation(data),
        primarySymbol == null ? null : String.valueOf(primarySymbol.getSource()));
  }

  private static String representation(Data data) {
    String representation = data.getDefaultValueRepresentation();
    return representation == null ? String.valueOf(data.getValue()) : representation;
  }
}
