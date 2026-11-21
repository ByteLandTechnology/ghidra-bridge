package app.byteland.ghidra.service.globalvariable;

import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import java.util.Set;

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
      String cursor,
      Set<String> fields) {
    public Query {
      if (scan == null) throw new IllegalArgumentException("scan is required");
      if (limit < 1 || limit > 1000) throw new IllegalArgumentException("limit must be in 1..1000");
      fields = fields == null ? null : Set.copyOf(fields);
    }

    public Query(
        AddressScanOptions scan,
        String name,
        String namespace,
        boolean caseSensitive,
        int limit,
        String cursor) {
      this(scan, name, namespace, caseSensitive, limit, cursor, null);
    }
  }

  /**
   * Mutation data to create or patch a global variable.
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

  default GlobalVariableResource getGlobalVariable(String address, Set<String> fields) {
    return getGlobalVariable(address);
  }

  /**
   * Returns one page of global variables that match the query.
   */
  Page<GlobalVariableResource> listGlobalVariables(Query query);

  default Page<GlobalVariableResource> listGlobalVariables(Query query, Set<String> fields) {
    return listGlobalVariables(
        fields == null
            ? query
            : new Query(
                query.scan(),
                query.name(),
                query.namespace(),
                query.caseSensitive(),
                query.limit(),
                query.cursor(),
                fields));
  }

  /**
   * Writes global variable definitions as specified by the write mode.
   */
  void writeGlobalVariable(Mutation mutation, WriteMode mode);

  /**
   * Deletes a global variable definition at the given address.
   */
  void deleteGlobalVariable(String address, boolean deleteSymbol);
}
