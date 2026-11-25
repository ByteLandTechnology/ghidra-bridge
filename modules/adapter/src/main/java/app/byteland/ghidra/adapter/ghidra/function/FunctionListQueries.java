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
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
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
    if (range.afterEnd(firstAddress)) {
      return scan.finish();
    }
    FunctionManager functionManager = context.currentProgram().getFunctionManager();
    if (firstAddress.isExternalAddress()
        && (cursorAddress == null || firstAddress.compareTo(cursorAddress) > 0)) {
      Function externalFunction = functionManager.getFunctionAt(firstAddress);
      if (externalFunction != null && !range.afterEnd(externalFunction.getEntryPoint())) {
        visitFunction(
            scan,
            externalFunction,
            externalFunction.getEntryPoint(),
            normalizedName,
            entryFunction,
            containsAddress,
            query);
        if (scan.stopped()) return scan.finish();
        cursorAddress = externalFunction.getEntryPoint();
      }
    }

    FunctionIterator functions = functionManager.getFunctions(firstAddress, true);
    while (functions.hasNext()) {
      Function function = functions.next();
      Address entryPoint = function.getEntryPoint();
      if (cursorAddress != null && entryPoint.compareTo(cursorAddress) <= 0) continue;
      if (range.afterEnd(entryPoint)) break;
      visitFunction(scan, function, entryPoint, normalizedName, entryFunction, containsAddress, query);
      if (scan.stopped()) break;
    }
    return scan.finish();
  }

  private void visitFunction(
      BoundedAddressScan<FunctionResource> scan,
      Function function,
      Address entryPoint,
      String normalizedName,
      Function entryFunction,
      Address containsAddress,
      FunctionQuery query) {
    String address = AddressUtil.canonicalAddress(entryPoint);
    String functionName = function.getName();
    FunctionResource match = null;
    if (normalizedName != null
        && !functionName.toLowerCase(Locale.ROOT).contains(normalizedName)) {
    } else if (entryFunction != null
        && !function.equals(entryFunction)
        && containsAddress == null) {
    } else if (containsAddress != null && !function.getBody().contains(containsAddress)) {
    } else if (query.external() != null && function.isExternal() != query.external()) {
    } else if (query.thunk() != null && function.isThunk() != query.thunk()) {
    } else {
      match =
          FunctionDescriptions.describe(
              context, function, entryPoint, address, functionName, query.includes());
    }
    scan.visit(address, address, match);
  }

  private Address parseAddress(String rawAddress) {
    return context.parseAddress(rawAddress);
  }
}
