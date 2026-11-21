package app.byteland.ghidra.adapter.ghidra.function;

import ghidra.program.model.listing.Function;

@FunctionalInterface
public interface FunctionResolver {
  Function resolveFunction(String rawAddress);

  default Function resolveFunction(String rawAddress, String target) {
    return resolveFunction(rawAddress);
  }
}
