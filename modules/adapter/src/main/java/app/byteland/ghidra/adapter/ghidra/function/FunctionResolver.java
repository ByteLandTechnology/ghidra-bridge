package app.byteland.ghidra.adapter.ghidra.function;

import ghidra.program.model.listing.Function;

/**
 * Resolves a Ghidra {@link Function} from its raw entry-point address text.
 */
@FunctionalInterface
public interface FunctionResolver {
  /**
   * Resolves the function whose entry point matches {@code rawAddress}.
   *
   * @param rawAddress raw function entry-point address text
   * @return resolved Ghidra {@link Function}
   */
  Function resolveFunction(String rawAddress);
}
