package app.byteland.ghidra.adapter.ghidra.function;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import ghidra.program.model.listing.Function;
import java.util.NoSuchElementException;

final class FunctionLookupQueries implements FunctionResolver {
  private final GhidraSession context;

  FunctionLookupQueries(GhidraSession context) {
    this.context = context;
  }

  @Override
  public Function resolveFunction(String rawAddress) {
    return resolveFunction(rawAddress, "/selector/entry");
  }

  @Override
  public Function resolveFunction(String rawAddress, String target) {
    Function function =
        context.script().getFunctionAt(context.parseAddress(rawAddress, target));
    if (function == null) {
      throw new NoSuchElementException("function not found: " + rawAddress);
    }
    return function;
  }
}
