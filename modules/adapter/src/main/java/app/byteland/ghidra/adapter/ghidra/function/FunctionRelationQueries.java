package app.byteland.ghidra.adapter.ghidra.function;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.CppSymbolNames;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.function.FunctionCallResource;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalReference;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

final class FunctionRelationQueries {
  private final FunctionResolver resolver;

  FunctionRelationQueries(FunctionResolver resolver) {
    this.resolver = resolver;
  }

  Page<FunctionCallResource> getCallers(String rawAddress, int limit, String cursor) {
    return getFunctionRelations(rawAddress, true, limit, cursor);
  }

  Page<FunctionCallResource> getCallees(String rawAddress, int limit, String cursor) {
    return getFunctionRelations(rawAddress, false, limit, cursor);
  }

  private Page<FunctionCallResource> getFunctionRelations(
      String rawAddress, boolean callers, int limit, String cursor) {
    Function function = resolver.resolveFunction(rawAddress);
    Program program = function.getProgram();
    ReferenceManager referenceManager = program.getReferenceManager();
    FunctionManager functionManager = program.getFunctionManager();
    Map<Address, FunctionSummary> summaries = new HashMap<>();
    Set<String> seenPairs = new HashSet<>();
    List<FunctionCallResource> rows = new ArrayList<>();
    if (callers) {
      collectCallers(function, referenceManager, functionManager, summaries, seenPairs, rows);
    } else {
      collectCallees(function, referenceManager, functionManager, summaries, seenPairs, rows);
    }
    rows.sort(
        Comparator.comparing(FunctionCallResource::entry)
            .thenComparing(
                FunctionCallResource::callSite,
                Comparator.nullsFirst(Comparator.naturalOrder())));
    return Page.paginate(
        rows, limit, cursor, FunctionCallResource::entry, FunctionCallResource::callSite);
  }

  private static void collectCallers(
      Function targetFunction,
      ReferenceManager referenceManager,
      FunctionManager functionManager,
      Map<Address, FunctionSummary> summaries,
      Set<String> seenPairs,
      List<FunctionCallResource> rows) {
    ReferenceIterator iterator = referenceManager.getReferencesTo(targetFunction.getEntryPoint());
    while (iterator.hasNext()) {
      Reference reference = iterator.next();
      if (!reference.getReferenceType().isCall()) {
        continue;
      }
      Address fromAddress = reference.getFromAddress();
      Function caller = functionManager.getFunctionContaining(fromAddress);
      if (caller == null) {
        continue;
      }
      addRow(
          caller,
          AddressUtil.canonicalAddress(fromAddress),
          FunctionCallResource.Direction.CALLERS,
          summaries,
          seenPairs,
          rows);
    }
  }

  private static void collectCallees(
      Function sourceFunction,
      ReferenceManager referenceManager,
      FunctionManager functionManager,
      Map<Address, FunctionSummary> summaries,
      Set<String> seenPairs,
      List<FunctionCallResource> rows) {
    AddressIterator sources =
        referenceManager.getReferenceSourceIterator(sourceFunction.getBody(), true);
    while (sources.hasNext()) {
      Address fromAddress = sources.next();
      String callSite = AddressUtil.canonicalAddress(fromAddress);
      for (Reference reference : referenceManager.getReferencesFrom(fromAddress)) {
        if (!reference.getReferenceType().isCall()) {
          continue;
        }
        Function callee = resolveCallee(functionManager, reference);
        if (callee == null) {
          continue;
        }
        addRow(
            callee,
            callSite,
            FunctionCallResource.Direction.CALLEES,
            summaries,
            seenPairs,
            rows);
      }
    }
  }

  private static Function resolveCallee(FunctionManager functionManager, Reference reference) {
    Function callee = functionManager.getFunctionAt(reference.getToAddress());
    if (callee != null) {
      return callee;
    }
    if (reference instanceof ExternalReference externalReference) {
      ExternalLocation location = externalReference.getExternalLocation();
      if (location != null) {
        return location.getFunction();
      }
    }
    return null;
  }

  private static void addRow(
      Function relatedFunction,
      String callSite,
      FunctionCallResource.Direction direction,
      Map<Address, FunctionSummary> summaries,
      Set<String> seenPairs,
      List<FunctionCallResource> rows) {
    FunctionSummary summary =
        summaries.computeIfAbsent(
            relatedFunction.getEntryPoint(), ignored -> summarize(relatedFunction));
    String pairKey = Page.compositeKey(summary.entry(), callSite);
    if (!seenPairs.add(pairKey)) {
      return;
    }
    rows.add(
        new FunctionCallResource(
            summary.entry(),
            summary.name(),
            callSite,
            direction,
            summary.namespace(),
            summary.demangledName()));
  }

  private static FunctionSummary summarize(Function function) {
    Address entryPoint = function.getEntryPoint();
    String name = function.getName();
    return new FunctionSummary(
        AddressUtil.canonicalAddress(entryPoint),
        name,
        function.getParentNamespace().getName(true),
        CppSymbolNames.demangled(function.getProgram(), name, entryPoint));
  }

  private record FunctionSummary(
      String entry, String name, String namespace, String demangledName) {}
}
