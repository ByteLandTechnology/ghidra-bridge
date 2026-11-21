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
   * @param scan address range and timeout options
   * @param name optional symbol name substring filter
   * @param namespace optional symbol namespace filter
   * @param caseSensitive true for case-sensitive name matching
   * @param limit maximum items per page
   * @param cursor optional pagination cursor
   */
  record Query(
      AddressScanOptions scan,
      String name,
      String namespace,
      boolean caseSensitive,
      int limit,
      String cursor) {
    /** Validates scan options and page limit bounds. */
    public Query {
      if (scan == null) throw new IllegalArgumentException("scan is required");
      if (limit < 1 || limit > 1000) throw new IllegalArgumentException("limit must be in 1..1000");
    }
  }

  /**
   * Mutation data to create or patch a global variable.
   *
   * @param address target memory address
   * @param name optional symbol name to assign
   * @param dataType optional data type to apply
   */
  record Mutation(String address, String name, DataTypeReference dataType) {
    /** Validates address and mutation field requirements. */
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
    /** Requires no existing global variable at the target address. */
    CREATE,
    /** Requires an existing global variable at the target address. */
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
   * @param query search criteria and page options
   * @return page of global variable resources
   */
  Page<GlobalVariableResource> listGlobalVariables(Query query);

  /**
   * Writes global variable definitions as specified by the write mode.
   *
   * @param mutation address, name, and data type changes
   * @param mode create, patch, or upsert behavior
   */
  void writeGlobalVariable(Mutation mutation, WriteMode mode);

  /**
   * Deletes a global variable definition at the given address.
   *
   * @param address target memory address
   * @param deleteSymbol true to remove the primary label in addition to the data item
   */
  void deleteGlobalVariable(String address, boolean deleteSymbol);
}
