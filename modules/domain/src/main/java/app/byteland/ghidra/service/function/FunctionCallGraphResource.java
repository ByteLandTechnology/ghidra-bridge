package app.byteland.ghidra.service.function;

import app.byteland.ghidra.service.AddressScanOptions;
import java.util.List;

/**
 * Holds a bounded function call graph and its query parameters.
 */
public record FunctionCallGraphResource(
    String root,
    List<NodeResource> nodes,
    List<EdgeResource> edges,
    boolean limited,
    String stopReason,
    long elapsedMs) {
  public static final int DEFAULT_DEPTH = 2;
  public static final int MAX_DEPTH = 5;
  public static final int DEFAULT_MAX_NODES = 150;
  public static final int MAX_NODES = 500;
  public static final int DEFAULT_MAX_EDGES = 600;
  public static final int MAX_EDGES = 2000;

  public FunctionCallGraphResource {
    if (root == null || root.isBlank()) throw new IllegalArgumentException("root is required");
    nodes = nodes == null ? List.of() : List.copyOf(nodes);
    edges = edges == null ? List.of() : List.copyOf(edges);
    if (stopReason == null || stopReason.isBlank()) {
      throw new IllegalArgumentException("stopReason is required");
    }
    if (elapsedMs < 0) throw new IllegalArgumentException("elapsedMs must not be negative");
  }

  /**
   * Lists entry addresses whose caller or callee branches expand.
   */
  public record Expansion(List<String> callers, List<String> callees) {
    public Expansion {
      callers = callers == null ? List.of() : List.copyOf(callers);
      callees = callees == null ? List.of() : List.copyOf(callees);
    }
  }

  /**
   * Parameters for a bounded call graph query.
   */
  public record FunctionCallGraphQuery(
      String entry,
      int callersDepth,
      int calleesDepth,
      int maxNodes,
      int maxEdges,
      int timeoutMs,
      Expansion expansion) {
    public FunctionCallGraphQuery {
      if (entry == null || entry.isBlank()) {
        throw new IllegalArgumentException("entry is required");
      }
      if (callersDepth < 0 || callersDepth > MAX_DEPTH) {
        throw new IllegalArgumentException("callersDepth must be in 0.." + MAX_DEPTH);
      }
      if (calleesDepth < 0 || calleesDepth > MAX_DEPTH) {
        throw new IllegalArgumentException("calleesDepth must be in 0.." + MAX_DEPTH);
      }
      if (maxNodes < 1 || maxNodes > MAX_NODES) {
        throw new IllegalArgumentException("maxNodes must be in 1.." + MAX_NODES);
      }
      if (maxEdges < 1 || maxEdges > MAX_EDGES) {
        throw new IllegalArgumentException("maxEdges must be in 1.." + MAX_EDGES);
      }
      if (timeoutMs < AddressScanOptions.MIN_TIMEOUT_MS
          || timeoutMs > AddressScanOptions.MAX_TIMEOUT_MS) {
        throw new IllegalArgumentException(
            "timeoutMs must be in "
                + AddressScanOptions.MIN_TIMEOUT_MS
                + ".."
                + AddressScanOptions.MAX_TIMEOUT_MS);
      }
    }
  }

  /**
   * Expansion state and peer count for one branch direction.
   */
  public record BranchStateResource(boolean expanded, Integer count) {}

  /**
   * Caller and callee branch states on one graph node.
   */
  public record BranchesResource(BranchStateResource callers, BranchStateResource callees) {}

  /**
   * Function node in a call graph.
   */
  public record NodeResource(
      String entry,
      String name,
      String namespace,
      String demangledName,
      Integer callerDistance,
      Integer calleeDistance,
      BranchesResource branches) {
    public NodeResource {
      if (entry == null || entry.isBlank()) {
        throw new IllegalArgumentException("entry is required");
      }
      if (name == null || name.isBlank()) {
        throw new IllegalArgumentException("name is required");
      }
    }
  }

  /**
   * Directed call edge with deduplicated call site addresses.
   */
  public record EdgeResource(String from, String to, List<String> sites) {
    public EdgeResource {
      if (from == null || from.isBlank()) throw new IllegalArgumentException("from is required");
      if (to == null || to.isBlank()) throw new IllegalArgumentException("to is required");
      sites = sites == null ? List.of() : List.copyOf(sites);
    }
  }
}
