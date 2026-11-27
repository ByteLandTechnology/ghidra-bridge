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
import ghidra.program.model.listing.FunctionManager;
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
    Address explicitStart =
        query.scan().start() == null || query.scan().start().isBlank()
            ? null
            : parseAddress(query.scan().start());
    Address explicitEnd =
        query.scan().end() == null || query.scan().end().isBlank()
            ? null
            : parseAddress(query.scan().end());
    if (targetsExternalSpace(query, explicitStart, explicitEnd, cursorAddress, entryFunction)) {
      return listExternalFunctions(
          query,
          normalizedLimit,
          normalizedName,
          explicitStart,
          explicitEnd,
          cursorAddress,
          entryFunction,
          containsAddress);
    }
    AddressScanRanges.Resolved range =
        entryFunction != null
                && containsAddress == null
                && explicitStart == null
                && explicitEnd == null
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
    FunctionIterator functions = functionManager.getFunctions(firstAddress, true);
    while (functions.hasNext()) {
      Function function = functions.next();
      Address entryPoint = function.getEntryPoint();
      if (cursorAddress != null && entryPoint.compareTo(cursorAddress) <= 0) continue;
      if (range.afterEnd(entryPoint)) break;
      visitFunction(scan, function, normalizedName, entryFunction, containsAddress, query);
      if (scan.stopped()) break;
    }
    return scan.finish();
  }

  private static boolean targetsExternalSpace(
      FunctionQuery query,
      Address explicitStart,
      Address explicitEnd,
      Address cursorAddress,
      Function entryFunction) {
    if (explicitStart != null || explicitEnd != null) {
      boolean startExt = explicitStart != null && explicitStart.isExternalAddress();
      boolean endExt = explicitEnd != null && explicitEnd.isExternalAddress();
      if (explicitStart != null && explicitEnd != null && startExt != endExt) {
        throw new IllegalArgumentException("start and end must be in the same address space");
      }
      return startExt || endExt;
    }
    if (Boolean.TRUE.equals(query.external())) return true;
    if (cursorAddress != null && cursorAddress.isExternalAddress()) return true;
    return entryFunction != null && entryFunction.isExternal();
  }

  private Page<FunctionResource> listExternalFunctions(
      FunctionQuery query,
      int normalizedLimit,
      String normalizedName,
      Address explicitStart,
      Address explicitEnd,
      Address cursorAddress,
      Function entryFunction,
      Address containsAddress) {
    if (explicitStart != null && explicitEnd != null && explicitStart.compareTo(explicitEnd) > 0) {
      throw new IllegalArgumentException("start must not be greater than end");
    }

    Address singleTarget = null;
    if (explicitStart != null && explicitStart.equals(explicitEnd)) {
      singleTarget = explicitStart;
    } else if (explicitStart == null
        && explicitEnd == null
        && entryFunction != null
        && entryFunction.isExternal()
        && containsAddress == null) {
      singleTarget = entryFunction.getEntryPoint();
    }
    if (singleTarget != null) {
      String targetText = AddressUtil.canonicalAddress(singleTarget);
      BoundedAddressScan<FunctionResource> scan =
          BoundedAddressScan.start(
              normalizedLimit, query.scan().timeoutMs(), targetText, targetText);
      if (cursorAddress == null || singleTarget.compareTo(cursorAddress) > 0) {
        Function externalFunction =
            context.currentProgram().getFunctionManager().getFunctionAt(singleTarget);
        if (externalFunction == null
            && entryFunction != null
            && singleTarget.equals(entryFunction.getEntryPoint())) {
          externalFunction = entryFunction;
        }
        if (externalFunction != null) {
          visitFunction(
              scan, externalFunction, normalizedName, entryFunction, containsAddress, query);
        }
      }
      return scan.finish();
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
            : (externals.isEmpty() ? minExt : externals.getLast().getEntryPoint());

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
      visitFunction(scan, function, normalizedName, entryFunction, containsAddress, query);
      if (scan.stopped()) break;
    }
    return scan.finish();
  }

  private List<Function> collectExternalFunctions() {
    List<Function> externals = new ArrayList<>();
    FunctionIterator iterator =
        context.currentProgram().getFunctionManager().getExternalFunctions();
    while (iterator.hasNext()) {
      externals.add(iterator.next());
    }
    externals.sort(Comparator.comparing(Function::getEntryPoint));
    return externals;
  }

  private static void visitFunction(
      BoundedAddressScan<FunctionResource> scan,
      Function function,
      String normalizedName,
      Function entryFunction,
      Address containsAddress,
      FunctionQuery query) {
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
  }

  private Address parseAddress(String rawAddress) {
    return context.parseAddress(rawAddress);
  }
}
