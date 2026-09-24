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
   */
  record Query(
      AddressScanOptions scan,
      String name,
      String namespace,
      boolean caseSensitive,
      int limit,
      String cursor) {
    public Query {
      if (scan == null) throw new IllegalArgumentException("scan is required");
      if (limit < 1 || limit > 1000) throw new IllegalArgumentException("limit must be in 1..1000");
    }
  }

  /**
   * Mutation payload for creating or patching a global variable.
   */
  record Mutation(String address, String name, DataTypeReference dataType) {
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
    CREATE,
    PATCH,
    UPSERT
  }

  /**
   * Returns a global variable definition by address.
   */
  GlobalVariableResource getGlobalVariable(String address);

  /**
   * Returns one page of matching global variables.
   */
  Page<GlobalVariableResource> listGlobalVariables(Query query);

  /**
   * Writes global variable definitions according to the write mode.
   */
  void writeGlobalVariable(Mutation mutation, WriteMode mode);

  /**
   * Deletes a global variable definition at the given address.
   */
  void deleteGlobalVariable(String address, boolean deleteSymbol);
}
