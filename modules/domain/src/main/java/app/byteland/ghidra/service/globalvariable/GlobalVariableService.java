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
   * @param scan bounded address scan options
   * @param name optional symbol name filter
   * @param namespace optional namespace filter
   * @param caseSensitive whether name matching is case-sensitive
   * @param limit maximum items to return in 1..1000
   * @param cursor optional pagination cursor
   */
  record Query(
      AddressScanOptions scan,
      String name,
      String namespace,
      boolean caseSensitive,
      int limit,
      String cursor) {
    /** Validates scan presence and page size bounds. */
    public Query {
      if (scan == null) throw new IllegalArgumentException("scan is required");
      if (limit < 1 || limit > 1000) throw new IllegalArgumentException("limit must be in 1..1000");
    }
  }

  /**
   * Mutation data to create or patch a global variable.
   *
   * @param address target global variable address
   * @param name optional symbol name to assign
   * @param dataType optional data type to apply
   */
  record Mutation(String address, String name, DataTypeReference dataType) {
    /** Validates required address and at least one non-blank mutation field. */
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
    /** Requires no existing global variable definition at the address. */
    CREATE,
    /** Requires an existing global variable definition at the address. */
    PATCH,
    /** Creates or updates a global variable definition at the address. */
    UPSERT
  }

  /**
   * Returns a global variable definition by address.
   *
   * @param address target global variable address
   * @return global variable resource
   */
  GlobalVariableResource getGlobalVariable(String address);

  /**
   * Returns one page of global variables that match the query.
   *
   * @param query search filters and pagination options
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
   * @param address target global variable address
   * @param deleteSymbol whether to also delete the primary label at the address
   */
  void deleteGlobalVariable(String address, boolean deleteSymbol);
}
