package app.byteland.ghidra.adapter.ghidra.function;

import ghidra.program.model.listing.Function;

/** Resolves a Ghidra {@link Function} from a raw entry or body address string. */
@FunctionalInterface
public interface FunctionResolver {
  /**
   * Resolves the function identified by {@code rawAddress}.
   *
   * @param rawAddress raw function address text
   * @return resolved {@link Function}
   */
  Function resolveFunction(String rawAddress);
}
