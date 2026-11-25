package app.byteland.ghidra.service.function;

import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import java.util.List;
import java.util.Set;

/**
 * Manages functions, parameters, local variables, and call graphs.
 */
public interface FunctionService {
  /** Maximum UTF-8 byte length accepted for a C function prototype signature. */
  int MAX_SIGNATURE_BYTES = 8_192;

  /**
   * Parameter definition for atomic function prototype updates.
   */
  record ParameterPatch(
      String name, DataTypeReference dataType, VariableStorageReference storage) {
    public ParameterPatch {
      if (dataType == null) {
        throw new IllegalArgumentException("parameter dataType is required");
      }
      name = name == null || name.isBlank() ? null : name.trim();
    }
  }

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
      Set<String> includes) {
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

  /** Creates a function at an entry address. */
  FunctionResource createFunction(String rawAddress, String name, boolean disassemble);

  /** Deletes a function at its entry address. */
  void deleteFunction(String rawAddress);

  /**
   * Updates function name, comments, signature, and attributes.
   */
  default void patchFunction(
      String rawAddress,
      String newName,
      String newComment,
      boolean commentPresent,
      DataTypeReference returnType,
      VariableStorageReference returnStorage,
      String callingConvention,
      FunctionAttributePatch attributes) {
    patchFunction(
        rawAddress,
        newName,
        newComment,
        commentPresent,
        null,
        returnType,
        returnStorage,
        callingConvention,
        attributes);
  }

  /**
   * Updates function name, comments, C signature or structured signature fields, and attributes.
   */
  void patchFunction(
      String rawAddress,
      String newName,
      String newComment,
      boolean commentPresent,
      String signature,
      DataTypeReference returnType,
      VariableStorageReference returnStorage,
      String callingConvention,
      FunctionAttributePatch attributes);

  /**
   * Updates function name, comments, C signature or atomic parameter list, and attributes.
   */
  default void patchFunction(
      String rawAddress,
      String newName,
      String newComment,
      boolean commentPresent,
      String signature,
      DataTypeReference returnType,
      VariableStorageReference returnStorage,
      String callingConvention,
      List<ParameterPatch> parameters,
      FunctionAttributePatch attributes) {
    if (parameters != null) {
      throw new UnsupportedOperationException("parameter list patch is not supported");
    }
    patchFunction(
        rawAddress,
        newName,
        newComment,
        commentPresent,
        signature,
        returnType,
        returnStorage,
        callingConvention,
        attributes);
  }

  /**
   * Returns one page of functions that call the target function.
   */
  Page<FunctionCallResource> getCallers(String rawAddress, int limit, String cursor);

  /**
   * Returns one page of functions called by the target function.
   */
  Page<FunctionCallResource> getCallees(String rawAddress, int limit, String cursor);

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
