package app.byteland.ghidra.adapter.ghidra;

import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

public final class ScriptSymbolRenamer {
  private ScriptSymbolRenamer() {}

  public static Symbol rename(GhidraSession context, Symbol symbol, String newName) {
    return renameBody(context, symbol, newName);
  }

  private static Symbol renameBody(GhidraSession context, Symbol symbol, String newName) {
    if (newName == null || newName.isBlank()) {
      throw new IllegalArgumentException("name is required");
    }
    String oldName = symbol.getName();
    if (oldName.equals(newName)) {
      return symbol;
    }

    if (SymbolType.FUNCTION.equals(symbol.getSymbolType())) {
      return renameFunctionSymbol(context, symbol, newName);
    }
    if (SymbolType.LABEL.equals(symbol.getSymbolType())) {
      return renameLabelSymbol(symbol, newName);
    }
    throw new IllegalArgumentException(
        "renaming " + symbol.getSymbolType() + " symbols is not supported by GhidraScript");
  }

  /**
   * Renames a label in place. The symbol keeps its id, namespace, primary state, and
   * references, so callers can read it again by id.
   */
  private static Symbol renameLabelSymbol(Symbol symbol, String newName) {
    try {
      symbol.setName(newName, SourceType.USER_DEFINED);
    } catch (DuplicateNameException | InvalidInputException ex) {
      throw new IllegalArgumentException("unable to rename symbol: " + ex.getMessage(), ex);
    }
    return symbol;
  }

  private static Symbol renameFunctionSymbol(GhidraSession context, Symbol symbol, String newName) {
    Symbol replacement =
        createLabel(
            context,
            symbol.getAddress(),
            newName,
            symbol.getParentNamespace(),
            true,
            "unable to rename function symbol");
    if (!SymbolType.FUNCTION.equals(replacement.getSymbolType())) {
      throw new IllegalArgumentException("script rename did not return a function symbol");
    }
    return replacement;
  }

  @SuppressWarnings("PMD.AvoidCatchingGenericException")
  private static Symbol createLabel(
      GhidraSession context,
      Address address,
      String name,
      Namespace namespace,
      boolean makePrimary,
      String failurePrefix) {
    try {
      if (namespace == null || namespace.isGlobal()) {
        return context.script().createLabel(address, name, makePrimary, SourceType.USER_DEFINED);
      }
      return context
          .script()
          .createLabel(address, name, namespace, makePrimary, SourceType.USER_DEFINED);
    } catch (RuntimeException ex) {
      throw ex;
    } catch (Exception ex) {
      throw new IllegalArgumentException(failurePrefix + ": " + ex.getMessage(), ex);
    }
  }
}
