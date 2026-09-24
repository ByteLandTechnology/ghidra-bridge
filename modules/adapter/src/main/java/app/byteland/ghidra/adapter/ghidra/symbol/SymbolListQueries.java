package app.byteland.ghidra.adapter.ghidra.symbol;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.scan.AddressScanRanges;
import app.byteland.ghidra.adapter.ghidra.scan.BoundedAddressScan;
import app.byteland.ghidra.adapter.ghidra.scan.CompositeCursor;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.symbol.SymbolResource;
import app.byteland.ghidra.service.symbol.SymbolService.SymbolQuery;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import java.util.Locale;

final class SymbolListQueries {
  private final GhidraSession context;

  SymbolListQueries(GhidraSession context) {
    this.context = context;
  }

  Page<SymbolResource> listSymbols(SymbolQuery query) {
    Address filterAddress = query.address() == null ? null : context.parseAddress(query.address());
    AddressScanRanges.Resolved range =
        filterAddress != null && query.scan().start() == null && query.scan().end() == null
            ? AddressScanRanges.of(filterAddress, filterAddress)
            : AddressScanRanges.resolve(context, query.scan(), false);
    CursorPosition cursor = parseCursor(query.cursor());
    Address iterationStart =
        cursor != null && cursor.address().compareTo(range.start()) > 0
            ? cursor.address()
            : range.start();
    String normalizedName =
        query.name() == null
            ? null
            : (query.caseSensitive() ? query.name() : query.name().toLowerCase(Locale.ROOT));
    BoundedAddressScan<SymbolResource> scan =
        BoundedAddressScan.start(
            query.limit(), query.scan().timeoutMs(), range.startText(), range.endText());

    SymbolIterator symbols =
        context.currentProgram().getSymbolTable().getSymbolIterator(iterationStart, true);
    while (symbols.hasNext()) {
      Symbol symbol = symbols.next();
      if (cursor != null && compare(symbol, cursor) <= 0) continue;
      if (range.afterEnd(symbol.getAddress())) break;
      String address = AddressUtil.canonicalAddress(symbol.getAddress());
      SymbolResource match =
          matchesSymbol(symbol, normalizedName, filterAddress, query)
              ? SymbolDescriptions.describe(symbol)
              : null;
      scan.visit(address, CompositeCursor.key(address, String.valueOf(symbol.getID())), match);
      if (scan.stopped()) break;
    }
    return scan.finish();
  }

  private static boolean matchesSymbol(
      Symbol symbol, String normalizedName, Address filterAddress, SymbolQuery query) {
    if (query.type() != null
        && symbol.getSymbolType() != null
        && !query.type().equalsIgnoreCase(symbol.getSymbolType().toString())) {
      return false;
    }
    if (query.namespace() != null
        && (symbol.getParentNamespace() == null
            || !query.namespace().equals(symbol.getParentNamespace().getName()))) {
      return false;
    }
    if (query.sourceType() != null
        && !query.sourceType().equalsIgnoreCase(String.valueOf(symbol.getSource()))) {
      return false;
    }
    String symbolName = symbol.getName();
    String valueName = query.caseSensitive() ? symbolName : symbolName.toLowerCase(Locale.ROOT);
    if (normalizedName != null && !valueName.contains(normalizedName)) return false;
    return filterAddress == null || symbol.getAddress().equals(filterAddress);
  }

  private CursorPosition parseCursor(String cursor) {
    CompositeCursor parts = CompositeCursor.parse(cursor, "symbols");
    if (parts == null) return null;
    try {
      return new CursorPosition(
          context.parseAddress(parts.address()), Long.parseLong(parts.secondary()));
    } catch (NumberFormatException error) {
      throw new IllegalArgumentException("invalid symbols cursor", error);
    }
  }

  private static int compare(Symbol symbol, CursorPosition cursor) {
    int byAddress = symbol.getAddress().compareTo(cursor.address());
    return byAddress == 0 ? Long.compare(symbol.getID(), cursor.id()) : byAddress;
  }

  private record CursorPosition(Address address, long id) {}
}
