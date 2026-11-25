package app.byteland.ghidra.adapter.ghidra.decompilation;

import app.byteland.ghidra.adapter.ghidra.GhidraDataTypeReferences;
import app.byteland.ghidra.service.function.FunctionResource;
import app.byteland.ghidra.service.function.VariableStorageReference;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.EquateSymbol;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;

/**
 * Extracts local variable symbols from a decompiler symbol map.
 */
public final class DecompilerLocalSymbols {
  private static final Comparator<FunctionResource.LocalVariableResource> LOCAL_ORDER =
      Comparator.comparing(FunctionResource.LocalVariableResource::name)
          .thenComparing(DecompilerLocalSymbols::storageKey);

  private DecompilerLocalSymbols() {}

  private static String storageKey(FunctionResource.LocalVariableResource item) {
    return switch (item.storage()) {
      case VariableStorageReference.Serialization s -> s.serialization();
      case VariableStorageReference.Register r -> r.register();
    };
  }

  public static boolean isLocalVariable(HighSymbol symbol) {
    if (symbol == null
        || symbol.isParameter()
        || symbol.isGlobal()
        || symbol instanceof EquateSymbol) {
      return false;
    }
    String name = symbol.getName();
    if (name == null || name.isBlank()) {
      return false;
    }
    VariableStorage storage = symbol.getStorage();
    return storage != null
        && !storage.isBadStorage()
        && !storage.isVoidStorage()
        && !storage.isAutoStorage();
  }

  public static List<HighSymbol> findByName(HighFunction highFunction, String variableName) {
    if (highFunction == null) return List.of();
    LocalSymbolMap symbolMap = highFunction.getLocalSymbolMap();
    if (symbolMap == null) return List.of();
    List<HighSymbol> matches = new ArrayList<>();
    Iterator<HighSymbol> symbols = symbolMap.getSymbols();
    while (symbols != null && symbols.hasNext()) {
      HighSymbol symbol = symbols.next();
      if (isLocalVariable(symbol) && Objects.equals(variableName, symbol.getName())) {
        matches.add(symbol);
      }
    }
    return List.copyOf(matches);
  }

  public static List<FunctionResource.LocalVariableResource> describeLocalVariables(
      HighFunction highFunction) {
    if (highFunction == null) return List.of();
    LocalSymbolMap symbolMap = highFunction.getLocalSymbolMap();
    if (symbolMap == null) return List.of();
    List<FunctionResource.LocalVariableResource> items = new ArrayList<>();
    Iterator<HighSymbol> symbols = symbolMap.getSymbols();
    while (symbols != null && symbols.hasNext()) {
      HighSymbol symbol = symbols.next();
      if (isLocalVariable(symbol)) {
        items.add(describe(symbol));
      }
    }
    items.sort(LOCAL_ORDER);
    return List.copyOf(items);
  }

  public static FunctionResource.LocalVariableResource describe(HighSymbol symbol) {
    DataType dataType = symbol.getDataType() == null ? DataType.DEFAULT : symbol.getDataType();
    return new FunctionResource.LocalVariableResource(
        symbol.getName(),
        GhidraDataTypeReferences.toReference(dataType),
        VariableStorageReference.serialization(symbol.getStorage().getSerializationString()));
  }
}
