package app.byteland.ghidra.service.symbol;

import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.Page;
import java.util.List;
import java.util.Set;

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
      String cursor,
      Set<String> fields) {
    public SymbolQuery {
      if (scan == null) throw new IllegalArgumentException("scan is required");
      if (limit < 1 || limit > 1000) throw new IllegalArgumentException("limit must be in 1..1000");
      fields = fields == null ? null : Set.copyOf(fields);
    }

    public SymbolQuery(
        AddressScanOptions scan,
        String name,
        String address,
        String type,
        String namespace,
        String sourceType,
        boolean caseSensitive,
        int limit,
        String cursor) {
      this(scan, name, address, type, namespace, sourceType, caseSensitive, limit, cursor, null);
    }
  }

  /**
   * Returns one page of symbols that match the query.
   */
  Page<SymbolResource> listSymbols(SymbolQuery query);

  /**
   * Returns one page of symbols that match the query with an optional field projection.
   */
  default Page<SymbolResource> listSymbols(SymbolQuery query, Set<String> fields) {
    if (fields == null && query.fields() == null) {
      return listSymbols(query);
    }
    return listSymbols(
        new SymbolQuery(
            query.scan(),
            query.name(),
            query.address(),
            query.type(),
            query.namespace(),
            query.sourceType(),
            query.caseSensitive(),
            query.limit(),
            query.cursor(),
            fields));
  }

  /**
   * Returns symbol details by unique symbol identifier.
   */
  SymbolResource getSymbol(long symbolId);

  /**
   * Returns symbol details by unique symbol identifier with an optional field projection.
   */
  default SymbolResource getSymbol(long symbolId, Set<String> fields) {
    return getSymbol(symbolId);
  }

  /**
   * Renames a symbol by its unique identifier.
   */
  void renameSymbol(long symbolId, String newName);

  /** Applies native C++ names without function or data type changes. */
  DemangleResult demangleSymbols();

  record DemangleResult(int renamed, int failed, List<String> failures) {
    public DemangleResult {
      failures = List.copyOf(failures);
    }
  }
}
