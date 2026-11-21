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
   * @param scan address range and timeout options
   * @param name optional symbol name substring filter
   * @param address optional exact symbol address filter
   * @param type optional symbol type filter
   * @param namespace optional namespace filter
   * @param sourceType optional symbol source classification filter
   * @param caseSensitive true for case-sensitive name matching
   * @param limit maximum items per page
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
   * @param query symbol search criteria and pagination options
   * @return page of symbol resources
   */
  Page<SymbolResource> listSymbols(SymbolQuery query);

  /**
   * Returns symbol details by unique symbol identifier.
   *
   * @param symbolId unique Ghidra symbol ID
   * @return symbol resource details
   */
  SymbolResource getSymbol(long symbolId);

  /**
   * Renames a symbol by its unique identifier.
   *
   * @param symbolId unique Ghidra symbol ID
   * @param newName replacement symbol name
   */
  void renameSymbol(long symbolId, String newName);

  /**
   * Applies native C++ names without function or data type changes.
   *
   * @return summary counts and failure descriptions
   */
  DemangleResult demangleSymbols();

  /**
   * Summarizes symbol demangling results across the program.
   *
   * @param renamed count of symbols renamed
   * @param failed count of symbols that failed to rename
   * @param failures diagnostic messages for failed renames
   */
  record DemangleResult(int renamed, int failed, List<String> failures) {
    /** Copies failure messages into an immutable list. */
    public DemangleResult {
      failures = List.copyOf(failures);
    }
  }
}
