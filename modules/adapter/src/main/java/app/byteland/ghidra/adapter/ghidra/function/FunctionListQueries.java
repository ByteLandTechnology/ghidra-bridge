package app.byteland.ghidra.adapter.ghidra.function;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.scan.AddressScanRanges;
import app.byteland.ghidra.adapter.ghidra.scan.BoundedAddressScan;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.function.FunctionResource;
import app.byteland.ghidra.service.function.FunctionService.FunctionQuery;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import java.util.Locale;

final class FunctionListQueries {
  private final GhidraSession context;
  private final FunctionResolver resolver;

  FunctionListQueries(GhidraSession context, FunctionResolver resolver) {
    this.context = context;
    this.resolver = resolver;
  }

  Page<FunctionResource> listFunctions(FunctionQuery query) {
    int normalizedLimit = Page.clampLimit(query.limit());
    String normalizedName = FunctionQuerySupport.trimLower(query.name());
    Address cursorAddress =
        query.cursor() == null || query.cursor().isBlank() ? null : parseAddress(query.cursor());
    Function entryFunction = null;
    if (query.entry() != null && !query.entry().isBlank()) {
      entryFunction = resolver.resolveFunction(query.entry());
    }
    Address containsAddress =
        query.contains() == null || query.contains().isBlank()
            ? null
            : parseAddress(query.contains());
    Function containingFunction =
        containsAddress == null ? null : context.script().getFunctionContaining(containsAddress);
    boolean unboundedRange = query.scan().start() == null && query.scan().end() == null;
    AddressScanRanges.Resolved range;
    if (containingFunction != null && unboundedRange) {
      range =
          AddressScanRanges.of(
              containingFunction.getEntryPoint(), containingFunction.getEntryPoint());
    } else if (entryFunction != null && containsAddress == null && unboundedRange) {
      range = AddressScanRanges.of(entryFunction.getEntryPoint(), entryFunction.getEntryPoint());
    } else {
      range = AddressScanRanges.resolve(context, query.scan(), false);
    }

    BoundedAddressScan<FunctionResource> scan =
        BoundedAddressScan.start(
            normalizedLimit, query.scan().timeoutMs(), range.startText(), range.endText());

    if (containsAddress != null) {
      if (containingFunction != null) {
        Address entryPoint = containingFunction.getEntryPoint();
        boolean afterCursor = cursorAddress == null || entryPoint.compareTo(cursorAddress) > 0;
        if (afterCursor && range.includes(entryPoint)) {
          FunctionResource match =
              matchesCandidate(containingFunction, normalizedName, entryFunction, query)
                  ? FunctionDescriptions.describe(containingFunction, query.includes())
                  : null;
          String address = AddressUtil.canonicalAddress(entryPoint);
          scan.visit(address, address, match);
        }
      }
      return scan.finish();
    }

    Address firstAddress =
        cursorAddress != null && cursorAddress.compareTo(range.start()) > 0
            ? cursorAddress
            : range.start();
    for (Function function = firstFunction(firstAddress, cursorAddress != null);
        function != null;
        function = nextFunction(function)) {
      if (range.afterEnd(function.getEntryPoint())) break;
      FunctionResource match =
          matchesCandidate(function, normalizedName, entryFunction, query)
              ? FunctionDescriptions.describe(function, query.includes())
              : null;
      String address = AddressUtil.canonicalAddress(function.getEntryPoint());
      scan.visit(address, address, match);
      if (scan.stopped()) break;
    }
    return scan.finish();
  }

  private static boolean matchesCandidate(
      Function function, String normalizedName, Function entryFunction, FunctionQuery query) {
    if (normalizedName != null
        && !function.getName().toLowerCase(Locale.ROOT).contains(normalizedName)) {
      return false;
    }
    if (entryFunction != null && !function.equals(entryFunction)) {
      return false;
    }
    if (query.external() != null && function.isExternal() != query.external()) {
      return false;
    }
    return query.thunk() == null || function.isThunk() == query.thunk();
  }

  private Address parseAddress(String rawAddress) {
    return context.parseAddress(rawAddress);
  }

  private Function firstFunction(Address address, boolean resumeStrictlyAfter) {
    return resumeStrictlyAfter
        ? context.script().getFunctionAfter(address)
        : firstFunctionAtOrAfter(address);
  }

  private Function nextFunction(Function function) {
    return context.script().getFunctionAfter(function);
  }

  private Function firstFunctionAtOrAfter(Address cursorAddress) {
    Function function = context.script().getFunctionAt(cursorAddress);
    return function == null ? context.script().getFunctionAfter(cursorAddress) : function;
  }
}
