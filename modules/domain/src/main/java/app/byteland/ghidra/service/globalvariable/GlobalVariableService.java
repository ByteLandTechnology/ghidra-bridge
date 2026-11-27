package app.byteland.ghidra.service.globalvariable;

import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.datatype.DataTypeReference;

/**
 * Coordinates defined data items and primary labels.
 */
public interface GlobalVariableService {
  /**
   * Search criteria for global variable queries.
   *
   * @param scan address scan bounds and timeout options
   * @param name optional symbol name text filter
   * @param namespace optional namespace filter
   * @param caseSensitive {@code true} for case-sensitive name comparison
   * @param limit maximum global variables to return in {@code 1..1000}
   * @param cursor optional pagination cursor
   */
  record Query(
      AddressScanOptions scan,
      String name,
      String namespace,
      boolean caseSensitive,
      int limit,
      String cursor) {
    /** Validates scan options and limit bounds. */
    public Query {
      if (scan == null) throw new IllegalArgumentException("scan is required");
      if (limit < 1 || limit > 1000) throw new IllegalArgumentException("limit must be in 1..1000");
    }
  }

  /**
   * Mutation data to create or patch a global variable.
   *
   * @param address target memory address
   * @param name optional primary symbol name
   * @param dataType optional data type reference
   */
  record Mutation(String address, String name, DataTypeReference dataType) {
    /** Validates that address is present and at least one of name or dataType is supplied. */
    public Mutation {
      if (address == null || address.isBlank()) {
        throw new IllegalArgumentException("address is required");
      }
      if (name != null && name.isBlank())
        throw new IllegalArgumentException("name must not be blank");
      if (name == null && dataType == null) {
        throw new IllegalArgumentException("name or dataType is required");
      }
    }
  }

  /**
   * Write mode for global variable mutations.
   */
  enum WriteMode {
    /** Creates a new global variable and fails if defined data already exists. */
    CREATE,
    /** Updates a current global variable and fails if none exists. */
    PATCH,
    /** Creates or updates a global variable at the target address. */
    UPSERT
  }

  /**
   * Returns a global variable definition by address.
   *
   * @param address target memory address
   * @return global variable resource
   */
  GlobalVariableResource getGlobalVariable(String address);

  /**
   * Returns one page of global variables that match the query.
   *
   * @param query search filters and scan bounds
   * @return page of global variable resources
   */
  Page<GlobalVariableResource> listGlobalVariables(Query query);

  /**
   * Writes global variable definitions as specified by the write mode.
   *
   * @param mutation target address, name, and data type fields
   * @param mode create, patch, or upsert write mode
   */
  void writeGlobalVariable(Mutation mutation, WriteMode mode);

  /**
   * Deletes a global variable definition at the given address.
   *
   * @param address target memory address
   * @param deleteSymbol {@code true} to also delete the primary symbol at {@code address}
   */
  void deleteGlobalVariable(String address, boolean deleteSymbol);
}
