package app.byteland.ghidra.adapter.ghidra.function;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalManager;
import ghidra.program.model.symbol.Symbol;
import java.util.NoSuchElementException;

final class FunctionLookupQueries implements FunctionResolver {
  private final GhidraSession context;

  FunctionLookupQueries(GhidraSession context) {
    this.context = context;
  }

  @Override
  public Function resolveFunction(String rawAddress) {
    if (rawAddress == null || rawAddress.isBlank()) {
      throw new IllegalArgumentException("address is required");
    }
    Address address = context.parseAddress(rawAddress);
    Function function = context.currentProgram().getListing().getFunctionAt(address);
    if (function == null && address.isExternalAddress()) {
      function = resolveExternalFunction(address);
    }
    if (function == null) {
      throw new NoSuchElementException("function not found: " + rawAddress);
    }
    return function;
  }

  private Function resolveExternalFunction(Address address) {
    Program program = context.currentProgram();
    ExternalManager externalManager = program.getExternalManager();
    for (Symbol symbol : program.getSymbolTable().getSymbols(address)) {
      if (symbol.getObject() instanceof Function direct) {
        return direct;
      }
      ExternalLocation location = externalManager.getExternalLocation(symbol);
      if (location != null && location.getFunction() != null) {
        return location.getFunction();
      }
    }
    FunctionIterator externalFunctions = program.getFunctionManager().getExternalFunctions();
    while (externalFunctions.hasNext()) {
      Function candidate = externalFunctions.next();
      if (address.equals(candidate.getEntryPoint())) {
        return candidate;
      }
    }
    return null;
  }
}
