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
   *
   * @param isInline optional inline flag update
   * @param hasNoReturn optional no-return flag update
   * @param hasVarArgs optional varargs flag update
   * @param hasCustomVariableStorage optional custom storage flag update
   * @param stackPurgeSize optional stack purge size update
   */
  record FunctionAttributePatch(
      Boolean isInline,
      Boolean hasNoReturn,
      Boolean hasVarArgs,
      Boolean hasCustomVariableStorage,
      Integer stackPurgeSize) {
    /**
     * Returns an attribute patch with no fields set.
     *
     * @return empty attribute patch
     */
    public static FunctionAttributePatch empty() {
      return new FunctionAttributePatch(null, null, null, null, null);
    }
  }

  /**
   * Search criteria and filters for function list queries.
   *
   * @param scan bounded address-scan options
   * @param limit maximum items per page ({@code 1..1000})
   * @param cursor pagination cursor, or {@code null}
   * @param name optional function name filter
   * @param entry optional exact entry address filter
   * @param contains optional address that must fall within the function body
   * @param external optional external-function filter
   * @param thunk optional thunk-function filter
   * @param includes optional set of additional fields to project
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
      Set<String> includes) {
    /** Validates query bounds and normalizes {@code includes}. */
    public FunctionQuery {
      if (scan == null) throw new IllegalArgumentException("scan is required");
      if (limit < 1 || limit > 1000) throw new IllegalArgumentException("limit must be in 1..1000");
      includes = includes == null ? Set.of() : Set.copyOf(includes);
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
   * Returns function details by address.
   *
   * @param rawAddress function entry point address
   * @param includes optional field projection set
   * @return function resource details
   */
  FunctionResource getFunction(String rawAddress, Set<String> includes);

  /**
   * Creates a function at an entry address.
   *
   * @param rawAddress function entry point address
   * @param name optional function name, or {@code null} for default naming
   * @param disassemble whether to disassemble undefined bytes at the entry point first
   * @return created function resource
   */
  FunctionResource createFunction(String rawAddress, String name, boolean disassemble);

  /**
   * Deletes a function at its entry address.
   *
   * @param rawAddress function entry point address
   */
  void deleteFunction(String rawAddress);

  /**
   * Updates function name, comments, signature, and attributes.
   *
   * @param rawAddress function entry point address
   * @param newName optional updated function name
   * @param newComment updated function comment, or {@code null} to clear when {@code
   *     commentPresent} is {@code true}
   * @param commentPresent whether {@code newComment} should be applied
   * @param returnType optional updated return type
   * @param returnStorage optional updated custom return storage
   * @param callingConvention optional updated calling convention name
   * @param attributes optional boolean and integer attribute updates
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
   *
   * @param rawAddress function entry point address
   * @param limit maximum items per page
   * @param cursor pagination cursor, or {@code null}
   * @return page of caller relationships
   */
  Page<FunctionCallResource> getCallers(String rawAddress, int limit, String cursor);

  /**
   * Returns one page of functions called by the target function.
   *
   * @param rawAddress function entry point address
   * @param limit maximum items per page
   * @param cursor pagination cursor, or {@code null}
   * @return page of callee relationships
   */
  Page<FunctionCallResource> getCallees(String rawAddress, int limit, String cursor);

  /**
   * Updates a function parameter that exists.
   *
   * @param rawAddress function entry point address
   * @param ordinal zero-based parameter ordinal
   * @param newName optional updated parameter name
   * @param newDataType optional updated parameter data type
   * @param storage optional updated custom storage location
   */
  void patchParameter(
      String rawAddress,
      int ordinal,
      String newName,
      DataTypeReference newDataType,
      VariableStorageReference storage);

  /**
   * Adds a new parameter to a function signature.
   *
   * @param rawAddress function entry point address
   * @param ordinal zero-based insertion ordinal
   * @param parameterName optional parameter name
   * @param dataType parameter data type
   * @param storage optional custom storage location
   */
  void addParameter(
      String rawAddress,
      int ordinal,
      String parameterName,
      DataTypeReference dataType,
      VariableStorageReference storage);

  /**
   * Removes a parameter from a function signature.
   *
   * @param rawAddress function entry point address
   * @param ordinal zero-based parameter ordinal to remove
   */
  void removeParameter(String rawAddress, int ordinal);

  /**
   * Updates a local variable in a function.
   *
   * @param rawAddress function entry point address
   * @param variableName current local variable name
   * @param newName optional updated variable name
   * @param newDataType optional updated variable data type
   */
  void patchLocalVariable(
      String rawAddress, String variableName, String newName, DataTypeReference newDataType);
}
