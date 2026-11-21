package app.byteland.ghidra.adapter.ghidra.function;

import ghidra.program.model.listing.Function;

/**
 * Resolves a Ghidra {@link Function} from a raw entry-point address string.
 */
@FunctionalInterface
public interface FunctionResolver {
  /**
   * Resolves the function at {@code rawAddress}.
   *
   * @param rawAddress function entry-point address
   * @return resolved Ghidra function
   */
  Function resolveFunction(String rawAddress);
}
