package app.byteland.ghidra.adapter.ghidra.function;

import ghidra.program.model.listing.Function;

/**
 * Resolves a Ghidra {@link Function} from a raw entry-point address string.
 */
@FunctionalInterface
public interface FunctionResolver {
  /**
   * Finds the function at the given entry-point address.
   *
   * @param rawAddress raw entry-point address text
   * @return resolved {@link Function}
   */
  Function resolveFunction(String rawAddress);
}
