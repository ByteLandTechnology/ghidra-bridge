package app.byteland.ghidra.service.listing;

import java.util.List;

/**
 * Holds one basic block, its instructions, and its flow edges.
 */
public record BasicBlockResource(
    String start,
    String end,
    long length,
    String flowType,
    boolean unresolvedJump,
    boolean edgesLimited,
    List<InstructionSummary> instructions,
    List<FlowEdge> destinations) {
  public static final int DEFAULT_MAX_EDGES = 2000;
  public static final int MAX_EDGES = 4000;

  public BasicBlockResource {
    if (start == null || start.isBlank()) throw new IllegalArgumentException("start is required");
    if (end == null || end.isBlank()) throw new IllegalArgumentException("end is required");
    if (length < 1) throw new IllegalArgumentException("length must be positive");
    instructions = instructions == null ? List.of() : List.copyOf(instructions);
    destinations = destinations == null ? List.of() : List.copyOf(destinations);
  }

  /**
   * Summary of one instruction in a basic block.
   */
  public record InstructionSummary(
      String address,
      int length,
      String mnemonic,
      List<String> operands,
      String flowType,
      String fallThrough) {
    public InstructionSummary {
      if (address == null || address.isBlank()) {
        throw new IllegalArgumentException("address is required");
      }
      if (length < 1) throw new IllegalArgumentException("length must be positive");
      operands = operands == null ? List.of() : List.copyOf(operands);
    }
  }

  /**
   * Directed control-flow edge from a basic block.
   */
  public record FlowEdge(String from, String to, String type) {
    public FlowEdge {
      if (from == null || from.isBlank()) throw new IllegalArgumentException("from is required");
      if (to == null || to.isBlank()) throw new IllegalArgumentException("to is required");
      if (type == null || type.isBlank()) throw new IllegalArgumentException("type is required");
    }
  }
}
