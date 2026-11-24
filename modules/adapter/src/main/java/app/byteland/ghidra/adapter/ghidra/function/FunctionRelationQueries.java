package app.byteland.ghidra.adapter.ghidra.function;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.CppSymbolNames;
import app.byteland.ghidra.adapter.ghidra.scan.CompositeCursor;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.function.FunctionCallResource;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.task.TaskMonitor;
import java.util.HashSet;
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
    Page.Selector<CallEdge> selector = Page.selector(limit, cursor);
    Set<String> seenEntries = new HashSet<>();
    Program program = function.getProgram();
    if (program != null) {
      if (callers) {
        offerCallerReferences(function, program, selector, seenEntries);
      } else {
        offerCalleeReferences(function, program, selector, seenEntries);
      }
    }
    Iterable<Function> related =
        callers
            ? function.getCallingFunctions(TaskMonitor.DUMMY)
            : function.getCalledFunctions(TaskMonitor.DUMMY);
    for (Function relatedFunction : related) {
      String entry = AddressUtil.canonicalAddress(relatedFunction.getEntryPoint());
      if (seenEntries.add(entry)) {
        selector.offer(edgeCursorKey(entry, null), new CallEdge(relatedFunction, entry, null));
      }
    }
    FunctionCallResource.Direction direction =
        callers ? FunctionCallResource.Direction.CALLERS : FunctionCallResource.Direction.CALLEES;
    return selector.finish(edge -> toResource(edge, direction));
  }

  private static void offerCallerReferences(
      Function targetFunction,
      Program program,
      Page.Selector<CallEdge> selector,
      Set<String> seenEntries) {
    ReferenceManager refManager = program.getReferenceManager();
    FunctionManager functionManager = program.getFunctionManager();
    Set<EdgeKey> seenEdges = new HashSet<>();
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
      seenEntries.add(entry);
      if (seenEdges.add(new EdgeKey(entry, callSite))) {
        selector.offer(edgeCursorKey(entry, callSite), new CallEdge(caller, entry, callSite));
      }
    }
  }

  private static void offerCalleeReferences(
      Function callerFunction,
      Program program,
      Page.Selector<CallEdge> selector,
      Set<String> seenEntries) {
    AddressSetView body = callerFunction.getBody();
    if (body == null) {
      return;
    }
    ReferenceManager refManager = program.getReferenceManager();
    FunctionManager functionManager = program.getFunctionManager();
    Set<EdgeKey> seenEdges = new HashSet<>();
    AddressIterator sources = refManager.getReferenceSourceIterator(body, true);
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
        seenEntries.add(entry);
        if (seenEdges.add(new EdgeKey(entry, callSite))) {
          selector.offer(edgeCursorKey(entry, callSite), new CallEdge(callee, entry, callSite));
        }
      }
    }
  }

  private static String edgeCursorKey(String entry, String callSite) {
    return callSite == null ? entry : CompositeCursor.key(entry, callSite);
  }

  private static FunctionCallResource toResource(
      CallEdge edge, FunctionCallResource.Direction direction) {
    Function relatedFunction = edge.function();
    String name = relatedFunction.getName();
    return new FunctionCallResource(
        edge.entry(),
        name,
        edge.callSite(),
        direction,
        relatedFunction.getParentNamespace().getName(true),
        CppSymbolNames.demangled(
            relatedFunction.getProgram(), name, relatedFunction.getEntryPoint()));
  }

  private record CallEdge(Function function, String entry, String callSite) {}

  private record EdgeKey(String entry, String callSite) {}
}
