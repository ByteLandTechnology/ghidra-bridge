package app.byteland.ghidra.adapter.ghidra.function;

import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;

@FunctionalInterface
public interface HighFunctionReader {
  HighFunction read(Function function);
}
