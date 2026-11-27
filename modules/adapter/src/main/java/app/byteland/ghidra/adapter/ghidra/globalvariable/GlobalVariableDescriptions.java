package app.byteland.ghidra.adapter.ghidra.globalvariable;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.FieldProjections;
import app.byteland.ghidra.adapter.ghidra.GhidraDataTypeReferences;
import app.byteland.ghidra.service.globalvariable.GlobalVariableResource;
import ghidra.program.model.listing.Data;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import java.util.Set;

final class GlobalVariableDescriptions {
  private GlobalVariableDescriptions() {}

  static GlobalVariableResource describe(Data data, Symbol primarySymbol) {
    return describe(data, primarySymbol, null);
  }

  static GlobalVariableResource describe(Data data, Symbol primarySymbol, Set<String> fields) {
    String namespaceName = null;
    if (primarySymbol != null && FieldProjections.allows(fields, "namespace")) {
      Namespace namespace = primarySymbol.getParentNamespace();
      namespaceName = namespace == null ? null : namespace.getName();
    }
    return new GlobalVariableResource(
        FieldProjections.allows(fields, "address")
            ? AddressUtil.canonicalAddress(data.getAddress())
            : null,
        primarySymbol != null && FieldProjections.allows(fields, "name")
            ? primarySymbol.getName()
            : null,
        namespaceName,
        FieldProjections.allows(fields, "data_type")
            ? GhidraDataTypeReferences.toReference(data.getDataType())
            : null,
        FieldProjections.allows(fields, "length") ? data.getLength() : 0,
        FieldProjections.allows(fields, "value") ? String.valueOf(data.getValue()) : null,
        FieldProjections.allows(fields, "representation") ? representation(data) : null,
        primarySymbol != null && FieldProjections.allows(fields, "source_type")
            ? String.valueOf(primarySymbol.getSource())
            : null);
  }

  private static String representation(Data data) {
    String representation = data.getDefaultValueRepresentation();
    return representation == null ? String.valueOf(data.getValue()) : representation;
  }
}
