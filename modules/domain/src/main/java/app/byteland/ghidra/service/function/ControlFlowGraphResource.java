package app.byteland.ghidra.service.function;

import app.byteland.ghidra.service.ScanProgress;
import java.util.List;
import java.util.Objects;

/**
 * Holds basic blocks, graph nodes, and branch edges for one function.
 */
public record ControlFlowGraphResource(
    String entry,
    String name,
    String namespace,
    String demangledName,
    FunctionResource.Body body,
    boolean hasBody,
    int unresolvedJumps,
    List<BlockResource> blocks,
    List<NodeResource> nodes,
    List<EdgeResource> edges,
    ScanProgress scan) {
  public static final int MIN_MAX_INSTRUCTIONS = 1;
  public static final int DEFAULT_MAX_INSTRUCTIONS = 5000;
  public static final int MAX_MAX_INSTRUCTIONS = 10000;

  public ControlFlowGraphResource {
    Objects.requireNonNull(entry, "entry");
    Objects.requireNonNull(name, "name");
    if (unresolvedJumps < 0) {
      throw new IllegalArgumentException("unresolvedJumps must not be negative");
    }
    blocks = List.copyOf(Objects.requireNonNull(blocks, "blocks"));
    nodes = List.copyOf(Objects.requireNonNull(nodes, "nodes"));
    edges = List.copyOf(Objects.requireNonNull(edges, "edges"));
  }

  /**
   * Holds address and byte length for one instruction in a basic block.
   */
  public record BlockInstructionResource(String address, int length) {
    public BlockInstructionResource {
      Objects.requireNonNull(address, "address");
      if (length < 1) {
        throw new IllegalArgumentException("length must be positive");
      }
    }
  }

  /**
   * Holds instruction bounds for one basic block.
   */
  public record BlockResource(String address, List<BlockInstructionResource> instructions) {
    public BlockResource {
      Objects.requireNonNull(address, "address");
      instructions = List.copyOf(Objects.requireNonNull(instructions, "instructions"));
    }
  }

  /**
   * Holds one basic-block or external target node in a control-flow graph.
   */
  public record NodeResource(
      String id, String kind, String address, String entry, List<String> lines) {
    public NodeResource {
      Objects.requireNonNull(id, "id");
      Objects.requireNonNull(kind, "kind");
      Objects.requireNonNull(address, "address");
      lines = lines == null ? null : List.copyOf(lines);
    }
  }

  /**
   * Holds one directed branch or fall-through edge in a control-flow graph.
   */
  public record EdgeResource(String from, String to, String label, String kind) {
    public EdgeResource {
      Objects.requireNonNull(from, "from");
      Objects.requireNonNull(to, "to");
      Objects.requireNonNull(label, "label");
      Objects.requireNonNull(kind, "kind");
    }
  }
}
