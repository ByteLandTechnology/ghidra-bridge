package app.byteland.ghidra.adapter.ghidra.function;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.CppSymbolNames;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.QuerySnapshotCache;
import app.byteland.ghidra.adapter.ghidra.scan.CompositeCursor;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.function.FunctionCallResource;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalReference;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

final class FunctionRelationQueries {
  private static final String FUNCTION_CALL_RESOURCE = "function_call";

  record PeerCalls(String entry, Function function, List<String> callSites) {}

  record CollectedPeers(List<PeerCalls> peers, boolean timedOut) {}

  private final GhidraSession context;
  private final FunctionResolver resolver;

  FunctionRelationQueries(FunctionResolver resolver) {
    this(null, resolver);
  }

  FunctionRelationQueries(GhidraSession context, FunctionResolver resolver) {
    this.context = context;
    this.resolver = Objects.requireNonNull(resolver, "resolver");
  }

  Page<FunctionCallResource> getCallers(String rawAddress, int limit, String cursor) {
    return getFunctionRelations(rawAddress, true, limit, cursor);
  }

  Page<FunctionCallResource> getCallees(String rawAddress, int limit, String cursor) {
    return getFunctionRelations(rawAddress, false, limit, cursor);
  }

  private Page<FunctionCallResource> getFunctionRelations(
      String rawAddress, boolean callers, int limit, String cursor) {
    if (cursor != null && cursor.indexOf('\0') >= 0) {
      CompositeCursor.parse(cursor, FUNCTION_CALL_RESOURCE);
    }
    Function function = resolver.resolveFunction(rawAddress);
    boolean hasCursor = cursor != null && !cursor.isBlank();
    if (!hasCursor || context == null || !context.canCacheSnapshots()) {
      return selectRelationsBounded(function, callers, limit, cursor);
    }

    Program snapshotProgram = context.currentProgramOrNull();
    QuerySnapshotCache snapshots = context.querySnapshots();
    long clearEpoch = snapshots.clearEpoch();
    long modNumber = context.modificationNumber();
    String canonicalTarget = AddressUtil.canonicalAddress(function.getEntryPoint());
    String directionKey = callers ? "callers" : "callees";
    QuerySnapshotCache.Key cacheKey =
        QuerySnapshotCache.Key.of(
            FUNCTION_CALL_RESOURCE, modNumber, canonicalTarget, directionKey);
    String[] sortedKeys = snapshots.get(cacheKey);
    if (sortedKeys == null) {
      CollectedPeers collected = collectPeers(function, callers, Long.MAX_VALUE);
      List<String> keys = new ArrayList<>();
      for (PeerCalls peer : collected.peers()) {
        if (peer.callSites().isEmpty()) {
          keys.add(cursorKey(peer.entry(), null));
        } else {
          for (String site : peer.callSites()) {
            keys.add(cursorKey(peer.entry(), site));
          }
        }
      }
      sortedKeys = keys.toArray(String[]::new);
      Arrays.sort(sortedKeys);
      if (!context.canCacheSnapshots()) {
        return selectRelationsBounded(function, callers, limit, cursor);
      }
      if (context.currentProgramOrNull() == snapshotProgram
          && context.modificationNumber() == modNumber) {
        snapshots.putIfUnchanged(clearEpoch, cacheKey, sortedKeys);
      }
    }
    FunctionCallResource.Direction direction =
        callers ? FunctionCallResource.Direction.CALLERS : FunctionCallResource.Direction.CALLEES;
    Map<Function, PeerMetadata> metadataByFunction = new HashMap<>();
    return QuerySnapshotCache.slice(
        sortedKeys,
        limit,
        cursor,
        candidateKey -> resolveCandidateOrNull(snapshotProgram, candidateKey),
        candidate -> describeCandidate(candidate, direction, metadataByFunction));
  }

  private Page<FunctionCallResource> selectRelationsBounded(
      Function function, boolean callers, int limit, String cursor) {
    CollectedPeers collected = collectPeers(function, callers, Long.MAX_VALUE);
    Page.Selector<CandidateCall> selector = Page.selector(limit, cursor);
    for (PeerCalls peer : collected.peers()) {
      if (peer.callSites().isEmpty()) {
        selector.offer(
            cursorKey(peer.entry(), null), new CandidateCall(peer.entry(), peer.function(), null));
      } else {
        for (String site : peer.callSites()) {
          selector.offer(
              cursorKey(peer.entry(), site),
              new CandidateCall(peer.entry(), peer.function(), site));
        }
      }
    }
    FunctionCallResource.Direction direction =
        callers ? FunctionCallResource.Direction.CALLERS : FunctionCallResource.Direction.CALLEES;
    Map<Function, PeerMetadata> metadataByFunction = new HashMap<>();
    return selector.finish(
        candidate -> describeCandidate(candidate, direction, metadataByFunction));
  }

  private CandidateCall resolveCandidateOrNull(Program snapshotProgram, String candidateKey) {
    String entry;
    String callSite;
    if (candidateKey.indexOf('\0') >= 0) {
      CompositeCursor parts = CompositeCursor.parse(candidateKey, FUNCTION_CALL_RESOURCE);
      entry = parts.address();
      callSite = parts.secondary();
    } else {
      entry = candidateKey;
      callSite = null;
    }
    Function resolved = resolveFunctionOrNull(snapshotProgram, entry);
    return resolved == null ? null : new CandidateCall(entry, resolved, callSite);
  }

  private Function resolveFunctionOrNull(Program program, String canonicalEntry) {
    try {
      return resolver.resolveFunction(canonicalEntry);
    } catch (NoSuchElementException ignored) {
      if (program == null || Proxy.isProxyClass(program.getClass())) {
        return null;
      }
      try {
        Address address = AddressUtil.parseAddress(program, canonicalEntry);
        if (address.isExternalAddress()) {
          Symbol symbol = program.getSymbolTable().getPrimarySymbol(address);
          if (symbol != null) {
            ExternalLocation location = program.getExternalManager().getExternalLocation(symbol);
            return location == null ? null : location.getFunction();
          }
        }
      } catch (IllegalArgumentException ignoredParse) {
        return null;
      }
      return null;
    }
  }

  private static FunctionCallResource describeCandidate(
      CandidateCall candidate,
      FunctionCallResource.Direction direction,
      Map<Function, PeerMetadata> metadataByFunction) {
    PeerMetadata metadata =
        metadataByFunction.computeIfAbsent(candidate.function(), PeerMetadata::from);
    return new FunctionCallResource(
        candidate.entry(),
        metadata.name(),
        candidate.callSite(),
        direction,
        metadata.namespace(),
        metadata.demangled());
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
    if (program == null) return false;
    ReferenceManager refManager = referenceManagerOrNull(program);
    FunctionManager fnManager = functionManagerOrNull(program);
    if (refManager == null || fnManager == null) return false;
    ReferenceIterator refs = refManager.getReferencesTo(function.getEntryPoint());
    if (refs == null) return false;
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
      PeerAccumulator accumulator = null;
      if (refType.isCall()) {
        accumulator =
            peersByEntry.computeIfAbsent(callerEntry, ignored -> new PeerAccumulator(caller));
      } else if (!callerEntry.equals(AddressUtil.canonicalAddress(function.getEntryPoint()))) {
        accumulator = peersByEntry.get(callerEntry);
      }
      if (accumulator != null) {
        accumulator.callSites().add(AddressUtil.canonicalAddress(fromAddress));
      }
    }
    return false;
  }

  private static boolean collectCalleeSites(
      Function function, Map<String, PeerAccumulator> peersByEntry, long deadlineNanos) {
    Program program = function.getProgram();
    if (program == null) return false;
    AddressSetView body = bodyOrNull(function);
    if (body == null) return false;
    ReferenceManager refManager = referenceManagerOrNull(program);
    FunctionManager fnManager = functionManagerOrNull(program);
    if (refManager == null || fnManager == null) return false;
    AddressIterator sources = refManager.getReferenceSourceIterator(body, true);
    if (sources == null) return false;
    while (sources.hasNext()) {
      if (isExpired(deadlineNanos)) return true;
      Address sourceAddress = sources.next();
      String site = AddressUtil.canonicalAddress(sourceAddress);
      Reference[] outgoing = refManager.getReferencesFrom(sourceAddress);
      if (outgoing == null) continue;
      for (Reference reference : outgoing) {
        RefType refType = reference.getReferenceType();
        if (!refType.isCall() && !refType.isFlow()) continue;
        Function callee = resolveTargetFunction(fnManager, reference);
        if (callee == null) continue;
        String calleeEntry = AddressUtil.canonicalAddress(callee.getEntryPoint());
        PeerAccumulator accumulator = null;
        if (refType.isCall()) {
          accumulator =
              peersByEntry.computeIfAbsent(calleeEntry, ignored -> new PeerAccumulator(callee));
        } else if (!calleeEntry.equals(AddressUtil.canonicalAddress(function.getEntryPoint()))) {
          accumulator = peersByEntry.get(calleeEntry);
        }
        if (accumulator != null) {
          accumulator.callSites().add(site);
        }
      }
    }
    return false;
  }

  private static ReferenceManager referenceManagerOrNull(Program program) {
    try {
      return program.getReferenceManager();
    } catch (UnsupportedOperationException ignored) {
      return null;
    }
  }

  private static FunctionManager functionManagerOrNull(Program program) {
    try {
      return program.getFunctionManager();
    } catch (UnsupportedOperationException ignored) {
      return null;
    }
  }

  private static AddressSetView bodyOrNull(Function function) {
    try {
      return function.getBody();
    } catch (UnsupportedOperationException ignored) {
      return null;
    }
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

  static String cursorKey(String entry, String callSite) {
    return callSite == null ? entry : CompositeCursor.key(entry, callSite);
  }

  private static boolean isExpired(long deadlineNanos) {
    return deadlineNanos != Long.MAX_VALUE && System.nanoTime() >= deadlineNanos;
  }

  private record CandidateCall(String entry, Function function, String callSite) {}

  private record PeerMetadata(String name, String namespace, String demangled) {
    static PeerMetadata from(Function function) {
      String name = function.getName();
      return new PeerMetadata(
          name,
          function.getParentNamespace().getName(true),
          CppSymbolNames.demangled(function.getProgram(), name, function.getEntryPoint()));
    }
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
