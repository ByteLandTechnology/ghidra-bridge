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
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalReference;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

final class FunctionRelationQueries {
  record PeerCalls(String entry, Function function, List<String> callSites) {}

  record CollectedPeers(List<PeerCalls> peers, boolean timedOut) {}

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
    CompositeCursor.parse(cursor, "function_call");
    Function function = resolver.resolveFunction(rawAddress);
    CollectedPeers collected = collectPeers(function, callers, Long.MAX_VALUE);
    FunctionCallResource.Direction direction =
        callers ? FunctionCallResource.Direction.CALLERS : FunctionCallResource.Direction.CALLEES;
    List<FunctionCallResource> rows = new ArrayList<>();
    for (PeerCalls peer : collected.peers()) {
      Function peerFn = peer.function();
      String name = peerFn.getName();
      String namespace = peerFn.getParentNamespace().getName(true);
      String demangled =
          CppSymbolNames.demangled(peerFn.getProgram(), name, peerFn.getEntryPoint());
      if (peer.callSites().isEmpty()) {
        rows.add(new FunctionCallResource(peer.entry(), name, null, direction, namespace, demangled));
      } else {
        for (String site : peer.callSites()) {
          rows.add(
              new FunctionCallResource(peer.entry(), name, site, direction, namespace, demangled));
        }
      }
    }
    rows.sort(Comparator.comparing(FunctionRelationQueries::cursorKey));
    return Page.paginate(rows, limit, cursor, FunctionRelationQueries::cursorKey);
  }

  CollectedPeers collectPeers(Function function, boolean callers, long deadlineNanos) {
    TaskMonitor monitor =
        deadlineNanos == Long.MAX_VALUE ? TaskMonitor.DUMMY : new DeadlineMonitor(deadlineNanos);
    Map<String, PeerAccumulator> peersByEntry = new TreeMap<>();
    Set<Function> related =
        callers ? function.getCallingFunctions(monitor) : function.getCalledFunctions(monitor);
    if (monitor.isCancelled()) {
      return new CollectedPeers(List.of(), true);
    }
    for (Function peer : related) {
      if (isExpired(deadlineNanos)) {
        return new CollectedPeers(List.of(), true);
      }
      String entry = AddressUtil.canonicalAddress(peer.getEntryPoint());
      peersByEntry.computeIfAbsent(entry, ignored -> new PeerAccumulator(peer));
    }

    boolean timedOut =
        callers
            ? collectCallerSites(function, peersByEntry, deadlineNanos)
            : collectCalleeSites(function, peersByEntry, deadlineNanos);
    if (timedOut) {
      return new CollectedPeers(List.of(), true);
    }

    List<PeerCalls> peers = new ArrayList<>(peersByEntry.size());
    for (Map.Entry<String, PeerAccumulator> item : peersByEntry.entrySet()) {
      peers.add(
          new PeerCalls(
              item.getKey(),
              item.getValue().function(),
              List.copyOf(item.getValue().callSites())));
    }
    return new CollectedPeers(List.copyOf(peers), false);
  }

  private static boolean collectCallerSites(
      Function function, Map<String, PeerAccumulator> peersByEntry, long deadlineNanos) {
    Program program = function.getProgram();
    ReferenceManager refManager = program.getReferenceManager();
    FunctionManager fnManager = program.getFunctionManager();
    ReferenceIterator refs = refManager.getReferencesTo(function.getEntryPoint());
    while (refs.hasNext()) {
      if (isExpired(deadlineNanos)) return true;
      Reference reference = refs.next();
      Address fromAddress = reference.getFromAddress();
      if (fromAddress == null || !fromAddress.isMemoryAddress()) continue;
      RefType refType = reference.getReferenceType();
      if (!refType.isCall() && !refType.isFlow()) continue;
      Function caller = fnManager.getFunctionContaining(fromAddress);
      if (caller == null) continue;
      String callerEntry = AddressUtil.canonicalAddress(caller.getEntryPoint());
      PeerAccumulator accumulator =
          refType.isCall()
              ? peersByEntry.computeIfAbsent(callerEntry, ignored -> new PeerAccumulator(caller))
              : peersByEntry.get(callerEntry);
      if (accumulator != null) {
        accumulator.callSites().add(AddressUtil.canonicalAddress(fromAddress));
      }
    }
    return false;
  }

  private static boolean collectCalleeSites(
      Function function, Map<String, PeerAccumulator> peersByEntry, long deadlineNanos) {
    Program program = function.getProgram();
    ReferenceManager refManager = program.getReferenceManager();
    FunctionManager fnManager = program.getFunctionManager();
    AddressIterator sources = refManager.getReferenceSourceIterator(function.getBody(), true);
    while (sources.hasNext()) {
      if (isExpired(deadlineNanos)) return true;
      Address sourceAddress = sources.next();
      String site = AddressUtil.canonicalAddress(sourceAddress);
      for (Reference reference : refManager.getReferencesFrom(sourceAddress)) {
        RefType refType = reference.getReferenceType();
        if (!refType.isCall() && !refType.isFlow()) continue;
        Function callee = resolveTargetFunction(fnManager, reference);
        if (callee == null) continue;
        String calleeEntry = AddressUtil.canonicalAddress(callee.getEntryPoint());
        PeerAccumulator accumulator =
            refType.isCall()
                ? peersByEntry.computeIfAbsent(calleeEntry, ignored -> new PeerAccumulator(callee))
                : peersByEntry.get(calleeEntry);
        if (accumulator != null) {
          accumulator.callSites().add(site);
        }
      }
    }
    return false;
  }

  private static Function resolveTargetFunction(FunctionManager fnManager, Reference reference) {
    Address toAddress = reference.getToAddress();
    if (toAddress != null) {
      Function direct = fnManager.getFunctionAt(toAddress);
      if (direct != null) return direct;
    }
    if (reference instanceof ExternalReference externalRef) {
      ExternalLocation location = externalRef.getExternalLocation();
      if (location != null) return location.getFunction();
    }
    return null;
  }

  private static String cursorKey(FunctionCallResource resource) {
    return CompositeCursor.key(
        resource.entry(), resource.callSite() == null ? "-" : resource.callSite());
  }

  private static boolean isExpired(long deadlineNanos) {
    return deadlineNanos != Long.MAX_VALUE && System.nanoTime() >= deadlineNanos;
  }

  private record PeerAccumulator(Function function, TreeSet<String> callSites) {
    PeerAccumulator(Function function) {
      this(function, new TreeSet<>());
    }
  }

  private static final class DeadlineMonitor extends TaskMonitorAdapter {
    private final long deadlineNanos;

    DeadlineMonitor(long deadlineNanos) {
      super(true);
      this.deadlineNanos = deadlineNanos;
    }

    @Override
    public boolean isCancelled() {
      return System.nanoTime() >= deadlineNanos || super.isCancelled();
    }
  }
}
