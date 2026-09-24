package app.byteland.ghidra.service.symbol;

import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.Page;

/**
 * Lists, reads, and renames program symbols.
 */
public interface SymbolService {
  /**
   * Search criteria and filters for symbol queries.
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
    public SymbolQuery {
      if (scan == null) throw new IllegalArgumentException("scan is required");
      if (limit < 1 || limit > 1000) throw new IllegalArgumentException("limit must be in 1..1000");
    }
  }

  /**
   * Returns one page of matching symbols.
   */
  Page<SymbolResource> listSymbols(SymbolQuery query);

  /**
   * Returns symbol details by unique symbol identifier.
   */
  SymbolResource getSymbol(long symbolId);

  /**
   * Renames a symbol by its unique identifier.
   */
  void renameSymbol(long symbolId, String newName);
}
