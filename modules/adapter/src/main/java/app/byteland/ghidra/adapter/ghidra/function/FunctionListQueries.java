package app.byteland.ghidra.adapter.ghidra.function;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.scan.AddressScanRanges;
import app.byteland.ghidra.adapter.ghidra.scan.BoundedAddressScan;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.function.FunctionResource;
import app.byteland.ghidra.service.function.FunctionService.FunctionQuery;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
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
    if (targetsExternalSpace(query, cursorAddress, entryFunction)) {
      return listExternalFunctions(
          query, normalizedLimit, normalizedName, cursorAddress, entryFunction, containsAddress);
    }
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
      FunctionResource match =
          matchesFunction(function, query, normalizedName, entryFunction, containsAddress)
              ? FunctionDescriptions.describe(function, query.includes())
              : null;
      String address = AddressUtil.canonicalAddress(function.getEntryPoint());
      scan.visit(address, address, match);
      if (scan.stopped()) break;
    }
    return scan.finish();
  }

  private boolean targetsExternalSpace(
      FunctionQuery query, Address cursorAddress, Function entryFunction) {
    if (Boolean.TRUE.equals(query.external())) return true;
    if (cursorAddress != null && cursorAddress.isExternalAddress()) return true;
    if (entryFunction != null && entryFunction.isExternal()) return true;
    Address rawStart =
        query.scan().start() == null || query.scan().start().isBlank()
            ? null
            : parseAddress(query.scan().start());
    Address rawEnd =
        query.scan().end() == null || query.scan().end().isBlank()
            ? null
            : parseAddress(query.scan().end());
    return (rawStart != null && rawStart.isExternalAddress())
        || (rawEnd != null && rawEnd.isExternalAddress());
  }

  private Page<FunctionResource> listExternalFunctions(
      FunctionQuery query,
      int normalizedLimit,
      String normalizedName,
      Address cursorAddress,
      Function entryFunction,
      Address containsAddress) {
    Address explicitStart =
        query.scan().start() == null || query.scan().start().isBlank()
            ? null
            : parseAddress(query.scan().start());
    Address explicitEnd =
        query.scan().end() == null || query.scan().end().isBlank()
            ? null
            : parseAddress(query.scan().end());
    if ((explicitStart != null && !explicitStart.isExternalAddress())
        || (explicitEnd != null && !explicitEnd.isExternalAddress())) {
      if (Boolean.TRUE.equals(query.external())
          && (explicitStart == null || !explicitStart.isExternalAddress())
          && (explicitEnd == null || !explicitEnd.isExternalAddress())) {
        return BoundedAddressScan.<FunctionResource>start(
                normalizedLimit,
                query.scan().timeoutMs(),
                AddressUtil.canonicalAddress(explicitStart),
                AddressUtil.canonicalAddress(explicitEnd))
            .finish();
      }
      throw new IllegalArgumentException(
          "range start and end must use the same address space");
    }
    if (explicitStart != null && explicitEnd != null && explicitStart.compareTo(explicitEnd) > 0) {
      throw new IllegalArgumentException("range start must be at or before range end");
    }

    List<Function> externals = collectExternalFunctions();
    Address minExt =
        explicitStart != null
            ? explicitStart
            : (externals.isEmpty()
                ? AddressSpace.EXTERNAL_SPACE.getMinAddress()
                : externals.getFirst().getEntryPoint());
    Address maxExt =
        explicitEnd != null
            ? explicitEnd
            : (externals.isEmpty()
                ? minExt
                : externals.getLast().getEntryPoint());
    if (entryFunction != null
        && containsAddress == null
        && explicitStart == null
        && explicitEnd == null) {
      minExt = entryFunction.getEntryPoint();
      maxExt = entryFunction.getEntryPoint();
    }

    BoundedAddressScan<FunctionResource> scan =
        BoundedAddressScan.start(
            normalizedLimit,
            query.scan().timeoutMs(),
            AddressUtil.canonicalAddress(minExt),
            AddressUtil.canonicalAddress(maxExt));

    for (Function function : externals) {
      Address entry = function.getEntryPoint();
      if (entry.compareTo(minExt) < 0) continue;
      if (cursorAddress != null && entry.compareTo(cursorAddress) <= 0) continue;
      if (entry.compareTo(maxExt) > 0) break;
      FunctionResource match =
          matchesFunction(function, query, normalizedName, entryFunction, containsAddress)
              ? FunctionDescriptions.describe(function, query.includes())
              : null;
      String address = AddressUtil.canonicalAddress(entry);
      scan.visit(address, address, match);
      if (scan.stopped()) break;
    }
    return scan.finish();
  }

  private List<Function> collectExternalFunctions() {
    List<Function> externals = new ArrayList<>();
    FunctionIterator iterator = context.currentProgram().getFunctionManager().getExternalFunctions();
    while (iterator.hasNext()) {
      externals.add(iterator.next());
    }
    externals.sort(Comparator.comparing(Function::getEntryPoint));
    return externals;
  }

  private static boolean matchesFunction(
      Function function,
      FunctionQuery query,
      String normalizedName,
      Function entryFunction,
      Address containsAddress) {
    if (normalizedName != null
        && !function.getName().toLowerCase(Locale.ROOT).contains(normalizedName)) {
      return false;
    }
    if (entryFunction != null && !function.equals(entryFunction) && containsAddress == null) {
      return false;
    }
    if (containsAddress != null && !function.getBody().contains(containsAddress)) {
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
