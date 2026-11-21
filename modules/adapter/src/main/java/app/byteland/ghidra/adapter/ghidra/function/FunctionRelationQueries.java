package app.byteland.ghidra.adapter.ghidra.function;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.CppSymbolNames;
import app.byteland.ghidra.adapter.ghidra.scan.CompositeCursor;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.function.FunctionCallResource;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
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
    List<FunctionCallResource> rows =
        callers ? collectCallers(function) : collectCallees(function);
    rows.sort(
        Comparator.comparing(FunctionCallResource::entry)
            .thenComparing(row -> Objects.requireNonNullElse(row.callSite(), "")));
    return Page.paginate(
        rows,
        limit,
        cursor,
        row ->
            CompositeCursor.key(row.entry(), Objects.requireNonNullElse(row.callSite(), "")));
  }

  private static List<FunctionCallResource> collectCallers(Function targetFunction) {
    Program program = targetFunction.getProgram();
    ReferenceManager refManager = program.getReferenceManager();
    FunctionManager functionManager = program.getFunctionManager();
    Set<EdgeKey> seen = new LinkedHashSet<>();
    List<FunctionCallResource> rows = new ArrayList<>();
    ReferenceIterator refs = refManager.getReferencesTo(targetFunction.getEntryPoint());
    while (refs.hasNext()) {
      Reference ref = refs.next();
      if (!ref.getReferenceType().isCall()) {
        continue;
      }
      Address callSiteAddress = ref.getFromAddress();
      Function caller = functionManager.getFunctionContaining(callSiteAddress);
      if (caller == null) {
        continue;
      }
      String entry = AddressUtil.canonicalAddress(caller.getEntryPoint());
      String callSite = AddressUtil.canonicalAddress(callSiteAddress);
      if (seen.add(new EdgeKey(entry, callSite))) {
        rows.add(toResource(caller, entry, callSite, FunctionCallResource.Direction.CALLERS));
      }
    }
    return rows;
  }

  private static List<FunctionCallResource> collectCallees(Function callerFunction) {
    Program program = callerFunction.getProgram();
    ReferenceManager refManager = program.getReferenceManager();
    FunctionManager functionManager = program.getFunctionManager();
    Set<EdgeKey> seen = new LinkedHashSet<>();
    List<FunctionCallResource> rows = new ArrayList<>();
    AddressIterator sources = refManager.getReferenceSourceIterator(callerFunction.getBody(), true);
    for (Address fromAddress : sources) {
      String callSite = AddressUtil.canonicalAddress(fromAddress);
      for (Reference ref : refManager.getReferencesFrom(fromAddress)) {
        if (!ref.getReferenceType().isCall()) {
          continue;
        }
        Function callee = functionManager.getFunctionAt(ref.getToAddress());
        if (callee == null) {
          continue;
        }
        String entry = AddressUtil.canonicalAddress(callee.getEntryPoint());
        if (seen.add(new EdgeKey(entry, callSite))) {
          rows.add(toResource(callee, entry, callSite, FunctionCallResource.Direction.CALLEES));
        }
      }
    }
    return rows;
  }

  private static FunctionCallResource toResource(
      Function relatedFunction,
      String entry,
      String callSite,
      FunctionCallResource.Direction direction) {
    return new FunctionCallResource(
        entry,
        relatedFunction.getName(),
        callSite,
        direction,
        relatedFunction.getParentNamespace().getName(true),
        CppSymbolNames.demangled(
            relatedFunction.getProgram(),
            relatedFunction.getName(),
            relatedFunction.getEntryPoint()));
  }

  private record EdgeKey(String entry, String callSite) {}
}
