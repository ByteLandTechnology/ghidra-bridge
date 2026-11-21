package app.byteland.ghidra.adapter.ghidra.function;

import app.byteland.ghidra.service.function.FunctionSelector;
import ghidra.program.model.listing.Function;

@FunctionalInterface
public interface FunctionResolver {
  Function resolveFunction(String rawAddress);

  default Function resolveFunction(FunctionSelector selector) {
    if (selector instanceof FunctionSelector.Entry entry) {
      return resolveFunction(entry.entry());
    }
    throw new UnsupportedOperationException("selector lookup is not implemented");
  }
}
