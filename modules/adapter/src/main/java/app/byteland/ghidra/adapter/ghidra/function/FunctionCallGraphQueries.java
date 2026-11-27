package app.byteland.ghidra.adapter.ghidra.function;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.CppSymbolNames;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.function.FunctionCallGraphResource;
import app.byteland.ghidra.service.function.FunctionCallGraphResource.BranchStateResource;
import app.byteland.ghidra.service.function.FunctionCallGraphResource.BranchesResource;
import app.byteland.ghidra.service.function.FunctionCallGraphResource.EdgeResource;
import app.byteland.ghidra.service.function.FunctionCallGraphResource.Expansion;
import app.byteland.ghidra.service.function.FunctionCallGraphResource.FunctionCallGraphQuery;
import app.byteland.ghidra.service.function.FunctionCallGraphResource.NodeResource;
import ghidra.program.model.listing.Function;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

final class FunctionCallGraphQueries {
  private static final long NANOS_PER_MILLISECOND = 1_000_000L;

  private final GhidraSession context;
  private final FunctionResolver resolver;
  private final FunctionRelationQueries relationQueries;

  FunctionCallGraphQueries(
      GhidraSession context, FunctionResolver resolver, FunctionRelationQueries relationQueries) {
    this.context = context;
    this.resolver = resolver;
    this.relationQueries = relationQueries;
  }

  FunctionCallGraphResource getCallGraph(FunctionCallGraphQuery query) {
    long startedNanos = System.nanoTime();
    long deadlineNanos = startedNanos + query.timeoutMs() * NANOS_PER_MILLISECOND;
    Function root = resolver.resolveFunction(query.entry());
    String rootEntry = AddressUtil.canonicalAddress(root.getEntryPoint());

    Map<String, MutableNode> nodesByEntry = new LinkedHashMap<>();
    nodesByEntry.put(rootEntry, MutableNode.fromFunction(rootEntry, root));
    Map<EdgeKey, TreeSet<String>> edgesByKey = new LinkedHashMap<>();

    Set<String> seenCallers = new HashSet<>();
    Set<String> seenCallees = new HashSet<>();
    seenCallers.add(rootEntry);
    seenCallees.add(rootEntry);

    boolean interactive = query.expansion() != null;
    Set<String> expandedCallers =
        interactive ? canonicalEntries(query.expansion().callers()) : Set.of();
    Set<String> expandedCallees =
        interactive ? canonicalEntries(query.expansion().callees()) : Set.of();

    Deque<QueueItem> queue = new ArrayDeque<>();
    if (interactive) {
      queue.addLast(new QueueItem(rootEntry, root, true, 1, Integer.MAX_VALUE));
      queue.addLast(new QueueItem(rootEntry, root, false, 1, Integer.MAX_VALUE));
    } else {
      if (query.callersDepth() > 0) {
        queue.addLast(new QueueItem(rootEntry, root, true, 1, query.callersDepth()));
      }
      if (query.calleesDepth() > 0) {
        queue.addLast(new QueueItem(rootEntry, root, false, 1, query.calleesDepth()));
      }
    }

    boolean limited = false;
    String stopReason = null;

    while (!queue.isEmpty()) {
      QueueItem item = queue.removeFirst();
      MutableNode sourceNode = nodesByEntry.get(item.entry());
      if (interactive) {
        boolean isExpanded =
            (item.callers() ? expandedCallers : expandedCallees).contains(item.entry());
        if (sourceNode != null) {
          sourceNode.setBranch(item.callers(), new BranchStateResource(isExpanded, null));
        }
        if (!isExpanded) {
          continue;
        }
      }

      if (System.nanoTime() >= deadlineNanos) {
        limited = true;
        if (stopReason == null) stopReason = "timeout";
        break;
      }

      FunctionRelationQueries.CollectedPeers collected =
          relationQueries.collectPeers(item.function(), item.callers(), deadlineNanos);
      if (collected.timedOut()) {
        limited = true;
        if (stopReason == null) stopReason = "timeout";
        break;
      }

      if (interactive && sourceNode != null) {
        sourceNode.setBranch(
            item.callers(), new BranchStateResource(true, collected.peers().size()));
      }

      for (FunctionRelationQueries.PeerCalls peer : collected.peers()) {
        String from = item.callers() ? peer.entry() : item.entry();
        String to = item.callers() ? item.entry() : peer.entry();
        EdgeKey edgeKey = new EdgeKey(from, to);
        if (!edgesByKey.containsKey(edgeKey) && edgesByKey.size() >= query.maxEdges()) {
          limited = true;
          if (stopReason == null) stopReason = "max_edges";
          continue;
        }

        MutableNode targetNode = nodesByEntry.get(peer.entry());
        if (targetNode == null) {
          if (nodesByEntry.size() >= query.maxNodes()) {
            limited = true;
            if (stopReason == null) stopReason = "max_nodes";
            continue;
          }
          targetNode = MutableNode.fromFunction(peer.entry(), peer.function());
          nodesByEntry.put(peer.entry(), targetNode);
        }

        if (!peer.entry().equals(rootEntry)) {
          targetNode.recordDistance(item.callers(), item.distance());
        }

        TreeSet<String> sites = edgesByKey.computeIfAbsent(edgeKey, ignored -> new TreeSet<>());
        sites.addAll(peer.callSites());

        if (interactive) {
          enqueueIfUnseen(queue, seenCallers, peer, true, item.distance() + 1, item.maxDepth());
          enqueueIfUnseen(queue, seenCallees, peer, false, item.distance() + 1, item.maxDepth());
        } else if (item.distance() < item.maxDepth()) {
          Set<String> seen = item.callers() ? seenCallers : seenCallees;
          enqueueIfUnseen(
              queue, seen, peer, item.callers(), item.distance() + 1, item.maxDepth());
        }
      }
    }

    List<NodeResource> nodes = new ArrayList<>(nodesByEntry.size());
    for (MutableNode node : nodesByEntry.values()) {
      nodes.add(node.toResource());
    }
    List<EdgeResource> edges = new ArrayList<>(edgesByKey.size());
    for (Map.Entry<EdgeKey, TreeSet<String>> entry : edgesByKey.entrySet()) {
      edges.add(
          new EdgeResource(
              entry.getKey().from(), entry.getKey().to(), List.copyOf(entry.getValue())));
    }
    long elapsedMs = Math.max(0L, (System.nanoTime() - startedNanos) / NANOS_PER_MILLISECOND);
    String finalReason = limited ? (stopReason == null ? "max_nodes" : stopReason) : "completed";
    return new FunctionCallGraphResource(rootEntry, nodes, edges, limited, finalReason, elapsedMs);
  }

  private static void enqueueIfUnseen(
      Deque<QueueItem> queue,
      Set<String> seen,
      FunctionRelationQueries.PeerCalls peer,
      boolean callers,
      int distance,
      int maxDepth) {
    if (seen.add(peer.entry())) {
      queue.addLast(new QueueItem(peer.entry(), peer.function(), callers, distance, maxDepth));
    }
  }

  private Set<String> canonicalEntries(List<String> rawEntries) {
    if (rawEntries == null || rawEntries.isEmpty()) return Set.of();
    Set<String> canonical = new HashSet<>(rawEntries.size());
    for (String raw : rawEntries) {
      if (raw == null || raw.isBlank()) continue;
      try {
        canonical.add(AddressUtil.canonicalAddress(context.parseAddress(raw)));
      } catch (IllegalArgumentException ignored) {
        canonical.add(raw.trim());
      }
    }
    return canonical;
  }

  private record EdgeKey(String from, String to) {}

  private record QueueItem(
      String entry, Function function, boolean callers, int distance, int maxDepth) {}

  private static final class MutableNode {
    private final String entry;
    private final String name;
    private final String namespace;
    private final String demangledName;
    private Integer callerDistance;
    private Integer calleeDistance;
    private BranchStateResource callersBranch;
    private BranchStateResource calleesBranch;

    private MutableNode(String entry, String name, String namespace, String demangledName) {
      this.entry = entry;
      this.name = name;
      this.namespace = namespace;
      this.demangledName = demangledName;
    }

    static MutableNode fromFunction(String entry, Function function) {
      String name = function.getName();
      return new MutableNode(
          entry,
          name,
          function.getParentNamespace().getName(true),
          CppSymbolNames.demangled(function.getProgram(), name, function.getEntryPoint()));
    }

    void recordDistance(boolean callers, int distance) {
      if (callers) {
        callerDistance = callerDistance == null ? distance : Math.min(callerDistance, distance);
      } else {
        calleeDistance = calleeDistance == null ? distance : Math.min(calleeDistance, distance);
      }
    }

    void setBranch(boolean callers, BranchStateResource state) {
      if (callers) {
        callersBranch = state;
      } else {
        calleesBranch = state;
      }
    }

    NodeResource toResource() {
      BranchesResource branches =
          callersBranch == null && calleesBranch == null
              ? null
              : new BranchesResource(callersBranch, calleesBranch);
      return new NodeResource(
          entry, name, namespace, demangledName, callerDistance, calleeDistance, branches);
    }
  }
}
