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
    AddressScanRanges.Resolved range =
        entryFunction != null
                && containsAddress == null
                && query.scan().start() == null
                && query.scan().end() == null
            ? AddressScanRanges.of(entryFunction.getEntryPoint(), entryFunction.getEntryPoint())
            : AddressScanRanges.resolve(context, query.scan(), false);

    BoundedAddressScan<FunctionResource> scan =
        BoundedAddressScan.start(
            normalizedLimit, query.scan().timeoutMs(), range.startText(), range.endText());

    Address firstAddress =
        cursorAddress != null && cursorAddress.compareTo(range.start()) > 0
            ? cursorAddress
            : range.start();
    for (Function function = firstFunction(firstAddress, cursorAddress != null);
        function != null;
        function = nextFunction(function)) {
      if (range.afterEnd(function.getEntryPoint())) break;
      FunctionResource match = null;
      if (normalizedName != null
          && !function.getName().toLowerCase(Locale.ROOT).contains(normalizedName)) {
      } else if (entryFunction != null
          && !function.equals(entryFunction)
          && containsAddress == null) {
      } else if (containsAddress != null && !function.getBody().contains(containsAddress)) {
      } else if (query.external() != null && function.isExternal() != query.external()) {
      } else if (query.thunk() != null && function.isThunk() != query.thunk()) {
      } else {
        match = FunctionDescriptions.describe(function, query.includes());
      }
      String address = AddressUtil.canonicalAddress(function.getEntryPoint());
      scan.visit(address, address, match);
      if (scan.stopped()) break;
    }
    return scan.finish();
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
