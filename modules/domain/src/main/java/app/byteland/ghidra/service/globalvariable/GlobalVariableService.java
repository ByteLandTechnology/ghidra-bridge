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
   * @param scan bounded address-scan options
   * @param name optional symbol name filter
   * @param namespace optional namespace filter
   * @param caseSensitive whether {@code name} matching is case-sensitive
   * @param limit maximum items per page ({@code 1..1000})
   * @param cursor pagination cursor, or {@code null}
   */
  record Query(
      AddressScanOptions scan,
      String name,
      String namespace,
      boolean caseSensitive,
      int limit,
      String cursor) {
    /** Validates scan presence and page limit bounds. */
    public Query {
      if (scan == null) throw new IllegalArgumentException("scan is required");
      if (limit < 1 || limit > 1000) throw new IllegalArgumentException("limit must be in 1..1000");
    }
  }

  /**
   * Mutation data to create or patch a global variable.
   *
   * @param address target variable start address
   * @param name optional primary label name to set
   * @param dataType optional data type to apply
   */
  record Mutation(String address, String name, DataTypeReference dataType) {
    /** Validates address and mutation payload fields. */
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
    /** Requires no existing defined data item at the target address. */
    CREATE,
    /** Requires an existing defined data item at the target address. */
    PATCH,
    /** Creates or updates a defined data item at the target address. */
    UPSERT
  }

  /**
   * Returns a global variable definition by address.
   *
   * @param address variable start address
   * @return global variable resource
   */
  GlobalVariableResource getGlobalVariable(String address);

  /**
   * Returns one page of global variables that match the query.
   *
   * @param query global variable filter and scan options
   * @return page of matching global variables
   */
  Page<GlobalVariableResource> listGlobalVariables(Query query);

  /**
   * Writes global variable definitions as specified by the write mode.
   *
   * @param mutation target address, label, and data type changes
   * @param mode create, patch, or upsert semantics
   */
  void writeGlobalVariable(Mutation mutation, WriteMode mode);

  /**
   * Deletes a global variable definition at the given address.
   *
   * @param address variable start address
   * @param deleteSymbol whether to also delete user-defined symbols at the address
   */
  void deleteGlobalVariable(String address, boolean deleteSymbol);
}
