package app.byteland.ghidra.service.program;

import java.util.List;

/**
 * Describes one imported external function or symbol in the active program.
 *
 * @param address canonical external space address
 * @param library imported library or namespace name
 * @param name symbol name
 * @param originalName original imported symbol name when distinct or present
 * @param demangledName demangled symbol name when present
 * @param ordinal import ordinal when present
 * @param thunkAddresses canonical addresses of thunk functions in program memory
 * @param signature function prototype text when the import is a function
 * @param isFunction true when the import represents an external function
 */
public record ImportResource(
    String address,
    String library,
    String name,
    String originalName,
    String demangledName,
    Integer ordinal,
    List<String> thunkAddresses,
    String signature,
    boolean isFunction) {
  public ImportResource {
    thunkAddresses = thunkAddresses == null ? List.of() : List.copyOf(thunkAddresses);
  }
}
