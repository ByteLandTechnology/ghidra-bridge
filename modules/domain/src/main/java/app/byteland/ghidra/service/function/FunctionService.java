package app.byteland.ghidra.service.function;

import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import java.util.Set;

/**
 * Manages functions, parameters, local variables, and call graphs.
 */
public interface FunctionService {
  /**
   * Patch for Boolean and integer function attributes.
   */
  record FunctionAttributePatch(
      Boolean isInline,
      Boolean hasNoReturn,
      Boolean hasVarArgs,
      Boolean hasCustomVariableStorage,
      Integer stackPurgeSize) {
    public static FunctionAttributePatch empty() {
      return new FunctionAttributePatch(null, null, null, null, null);
    }
  }

  /**
   * Search criteria and filters for function list queries.
   */
  record FunctionQuery(
      AddressScanOptions scan,
      int limit,
      String cursor,
      String name,
      String entry,
      String contains,
      Boolean external,
      Boolean thunk,
      Set<String> includes,
      Set<String> fields) {
    public FunctionQuery {
      if (scan == null) throw new IllegalArgumentException("scan is required");
      if (limit < 1 || limit > 1000) throw new IllegalArgumentException("limit must be in 1..1000");
      includes = includes == null ? Set.of() : Set.copyOf(includes);
      fields = fields == null ? null : Set.copyOf(fields);
    }

    public FunctionQuery(
        AddressScanOptions scan,
        int limit,
        String cursor,
        String name,
        String entry,
        String contains,
        Boolean external,
        Boolean thunk,
        Set<String> includes) {
      this(scan, limit, cursor, name, entry, contains, external, thunk, includes, null);
    }
  }

  /**
   * Returns one page of functions that match the query.
   *
   * @param query search query filters
   * @return a page of function resources
   */
  Page<FunctionResource> listFunctions(FunctionQuery query);

  /**
   * Returns one page of functions that match the query with an optional field projection.
   */
  default Page<FunctionResource> listFunctions(FunctionQuery query, Set<String> fields) {
    if (fields == null && query.fields() == null) {
      return listFunctions(query);
    }
    return listFunctions(
        new FunctionQuery(
            query.scan(),
            query.limit(),
            query.cursor(),
            query.name(),
            query.entry(),
            query.contains(),
            query.external(),
            query.thunk(),
            query.includes(),
            fields));
  }

  /**
   * Returns function details by address.
   *
   * @param rawAddress function entry point address
   * @param includes optional field projection set
   * @return function resource details
   */
  FunctionResource getFunction(String rawAddress, Set<String> includes);

  /**
   * Returns function details by address with an optional field projection.
   */
  default FunctionResource getFunction(
      String rawAddress, Set<String> includes, Set<String> fields) {
    return getFunction(rawAddress, includes);
  }

  /** Creates a function at an entry address. */
  FunctionResource createFunction(String rawAddress, String name, boolean disassemble);

  /** Deletes a function at its entry address. */
  void deleteFunction(String rawAddress);

  /**
   * Updates function name, comments, signature, and attributes.
   */
  void patchFunction(
      String rawAddress,
      String newName,
      String newComment,
      boolean commentPresent,
      DataTypeReference returnType,
      VariableStorageReference returnStorage,
      String callingConvention,
      FunctionAttributePatch attributes);

  /**
   * Returns one page of functions that call the target function.
   */
  Page<FunctionCallResource> getCallers(String rawAddress, int limit, String cursor);

  /**
   * Returns one page of functions that call the target function with an optional projection.
   */
  default Page<FunctionCallResource> getCallers(
      String rawAddress, int limit, String cursor, Set<String> fields) {
    return getCallers(rawAddress, limit, cursor);
  }

  /**
   * Returns one page of functions called by the target function.
   */
  Page<FunctionCallResource> getCallees(String rawAddress, int limit, String cursor);

  /**
   * Returns one page of functions called by the target function with an optional projection.
   */
  default Page<FunctionCallResource> getCallees(
      String rawAddress, int limit, String cursor, Set<String> fields) {
    return getCallees(rawAddress, limit, cursor);
  }

  /**
   * Updates a function parameter that exists.
   */
  void patchParameter(
      String rawAddress,
      int ordinal,
      String newName,
      DataTypeReference newDataType,
      VariableStorageReference storage);

  /**
   * Adds a new parameter to a function signature.
   */
  void addParameter(
      String rawAddress,
      int ordinal,
      String parameterName,
      DataTypeReference dataType,
      VariableStorageReference storage);

  /**
   * Removes a parameter from a function signature.
   */
  void removeParameter(String rawAddress, int ordinal);

  /**
   * Updates a local variable in a function.
   */
  void patchLocalVariable(
      String rawAddress, String variableName, String newName, DataTypeReference newDataType);
}
