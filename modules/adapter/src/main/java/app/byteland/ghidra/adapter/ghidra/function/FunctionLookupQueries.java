package app.byteland.ghidra.adapter.ghidra.function;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.AmbiguousTargetException;
import app.byteland.ghidra.service.function.FunctionSelector;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolType;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.TreeMap;

public final class FunctionLookupQueries implements FunctionResolver {
  private static final String GLOBAL_NAMESPACE = "Global";

  private final GhidraSession context;

  public FunctionLookupQueries(GhidraSession context) {
    this.context = context;
  }

  @Override
  public Function resolveFunction(String rawAddress) {
    if (rawAddress == null || rawAddress.isBlank()) {
      throw new IllegalArgumentException("address is required");
    }
    Function function = context.script().getFunctionAt(context.parseAddress(rawAddress));
    if (function == null) {
      throw new NoSuchElementException("function not found: " + rawAddress);
    }
    return function;
  }

  @Override
  public Function resolveFunction(FunctionSelector selector) {
    if (selector == null) {
      throw new IllegalArgumentException("selector is required");
    }
    return switch (selector) {
      case FunctionSelector.Entry entry -> resolveFunction(entry.entry());
      case FunctionSelector.Containing containing -> resolveContaining(containing.address());
      case FunctionSelector.Symbol symbol ->
          resolveSymbol(symbol.name(), symbol.namespace(), "/selector");
    };
  }

  public Function resolveFlexible(String target, String errorTarget) {
    if (target == null || target.isBlank()) {
      throw new IllegalArgumentException("function filter is required");
    }
    String trimmed = target.trim();
    if (!trimmed.contains("::") && looksLikeAddress(trimmed)) {
      Address address = tryParseAddress(trimmed);
      if (address != null) {
        Function atEntry = context.script().getFunctionAt(address);
        if (atEntry != null) {
          return atEntry;
        }
        Function containing = context.script().getFunctionContaining(address);
        if (containing != null) {
          return containing;
        }
      }
    }
    if (hasFunctionSymbol(trimmed)) {
      return resolveSymbol(trimmed, null, errorTarget);
    }
    Address address = tryParseAddress(trimmed);
    if (address != null) {
      Function atEntry = context.script().getFunctionAt(address);
      if (atEntry != null) {
        return atEntry;
      }
      Function containing = context.script().getFunctionContaining(address);
      if (containing != null) {
        return containing;
      }
    }
    throw new NoSuchElementException("function not found: " + target);
  }

  private Function resolveContaining(String rawAddress) {
    if (rawAddress == null || rawAddress.isBlank()) {
      throw new IllegalArgumentException("address is required");
    }
    Function function = context.script().getFunctionContaining(context.parseAddress(rawAddress));
    if (function == null) {
      throw new NoSuchElementException("function not found at address: " + rawAddress);
    }
    return function;
  }

  private Function resolveSymbol(String rawName, String rawNamespace, String errorTarget) {
    String trimmedName = rawName.trim();
    String namespaceFilter =
        rawNamespace == null || rawNamespace.isBlank() ? null : rawNamespace.trim();
    String simpleName = trimmedName;
    if (namespaceFilter == null) {
      int separator = trimmedName.lastIndexOf("::");
      if (separator > 0 && separator + 2 < trimmedName.length()) {
        namespaceFilter = trimmedName.substring(0, separator).trim();
        simpleName = trimmedName.substring(separator + 2).trim();
      }
    }
    Program program = context.currentProgram();
    Map<String, Function> matchesByEntry = new TreeMap<>();
    SymbolIterator symbols = program.getSymbolTable().getSymbols(simpleName);
    while (symbols.hasNext()) {
      Symbol symbol = symbols.next();
      if (symbol.getSymbolType() != SymbolType.FUNCTION) {
        continue;
      }
      Function function = extractFunction(program, symbol);
      if (function == null || !matchesNamespace(function.getParentNamespace(), namespaceFilter)) {
        continue;
      }
      matchesByEntry.putIfAbsent(
          AddressUtil.canonicalAddress(function.getEntryPoint()), function);
    }
    if (matchesByEntry.isEmpty()) {
      throw new NoSuchElementException("function not found: " + rawName);
    }
    if (matchesByEntry.size() > 1) {
      List<String> candidates = new ArrayList<>(matchesByEntry.size());
      for (Map.Entry<String, Function> entry : matchesByEntry.entrySet()) {
        Function fn = entry.getValue();
        candidates.add(fn.getParentNamespace().getName(true) + "::" + fn.getName()
            + " (" + entry.getKey() + ")");
      }
      throw new AmbiguousTargetException(
          "ambiguous_function",
          "multiple functions match '" + simpleName + "'; set namespace or entry",
          errorTarget,
          candidates);
    }
    return matchesByEntry.values().iterator().next();
  }

  private boolean hasFunctionSymbol(String rawName) {
    String simpleName = rawName;
    int separator = rawName.lastIndexOf("::");
    if (separator > 0 && separator + 2 < rawName.length()) {
      simpleName = rawName.substring(separator + 2).trim();
    }
    SymbolIterator symbols = context.currentProgram().getSymbolTable().getSymbols(simpleName);
    while (symbols.hasNext()) {
      if (symbols.next().getSymbolType() == SymbolType.FUNCTION) {
        return true;
      }
    }
    return false;
  }

  private static Function extractFunction(Program program, Symbol symbol) {
    Object obj = symbol.getObject();
    if (obj instanceof Function fn) {
      return fn;
    }
    return program.getFunctionManager().getFunctionAt(symbol.getAddress());
  }

  private static boolean matchesNamespace(Namespace parent, String filter) {
    if (filter == null) {
      return true;
    }
    if (parent.isGlobal()) {
      return GLOBAL_NAMESPACE.equalsIgnoreCase(filter) || "::".equals(filter);
    }
    String fullPath = parent.getName(true);
    String normalizedFilter =
        filter.startsWith(GLOBAL_NAMESPACE + "::")
            ? filter.substring((GLOBAL_NAMESPACE + "::").length())
            : filter;
    return fullPath.equals(normalizedFilter) || parent.getName(false).equals(normalizedFilter);
  }

  private static boolean looksLikeAddress(String value) {
    if (value.startsWith("0x") || value.startsWith("0X")) {
      return true;
    }
    int colon = value.indexOf(':');
    return colon > 0 && colon == value.lastIndexOf(':');
  }

  private Address tryParseAddress(String rawAddress) {
    try {
      return context.parseAddress(rawAddress);
    } catch (IllegalArgumentException ignored) {
      return null;
    }
  }
}
