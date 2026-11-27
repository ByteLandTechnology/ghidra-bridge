package app.byteland.ghidra.service.symbol;

import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.Page;
import java.util.List;

/**
 * Lists, reads, and renames program symbols.
 */
public interface SymbolService {
  /**
   * Search criteria and filters for symbol queries.
   *
   * @param scan address scan bounds and timeout options
   * @param name optional symbol name text filter
   * @param address optional exact symbol address filter
   * @param type optional Ghidra symbol type filter
   * @param namespace optional parent namespace filter
   * @param sourceType optional Ghidra symbol source filter
   * @param caseSensitive {@code true} for case-sensitive name comparison
   * @param limit maximum symbols to return in {@code 1..1000}
   * @param cursor optional pagination cursor
   */
  record SymbolQuery(
      AddressScanOptions scan,
      String name,
      String address,
      String type,
      String namespace,
      String sourceType,
      boolean caseSensitive,
      int limit,
      String cursor) {
    /** Validates scan options and page limit bounds. */
    public SymbolQuery {
      if (scan == null) throw new IllegalArgumentException("scan is required");
      if (limit < 1 || limit > 1000) throw new IllegalArgumentException("limit must be in 1..1000");
    }
  }

  /**
   * Returns one page of symbols that match the query.
   *
   * @param query symbol search filters and pagination options
   * @return page of symbol resources
   */
  Page<SymbolResource> listSymbols(SymbolQuery query);

  /**
   * Returns symbol details by unique symbol identifier.
   *
   * @param symbolId unique numeric symbol identifier
   * @return symbol resource
   */
  SymbolResource getSymbol(long symbolId);

  /**
   * Renames a symbol by its unique identifier.
   *
   * @param symbolId unique numeric symbol identifier
   * @param newName replacement symbol name
   */
  void renameSymbol(long symbolId, String newName);

  /**
   * Applies native C++ names without function or data type changes.
   *
   * @return summary counts and failure diagnostics from the demangle pass
   */
  DemangleResult demangleSymbols();

  /**
   * Summary counts and failure diagnostics from {@link #demangleSymbols()}.
   *
   * @param renamed count of symbols renamed to demangled names
   * @param failed count of mangled symbols that failed to rename
   * @param failures diagnostic descriptions for failed symbol renames
   */
  record DemangleResult(int renamed, int failed, List<String> failures) {
    /** Copies failure diagnostic strings into an immutable list. */
    public DemangleResult {
      failures = List.copyOf(failures);
    }
  }
}
