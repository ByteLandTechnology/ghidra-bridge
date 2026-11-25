package app.byteland.ghidra.adapter.ghidra.function;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.CppSymbolNames;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.ScanProgress;
import app.byteland.ghidra.service.function.ControlFlowGraphResource;
import app.byteland.ghidra.service.function.ControlFlowGraphResource.BlockInstructionResource;
import app.byteland.ghidra.service.function.ControlFlowGraphResource.BlockResource;
import app.byteland.ghidra.service.function.ControlFlowGraphResource.EdgeResource;
import app.byteland.ghidra.service.function.ControlFlowGraphResource.NodeResource;
import app.byteland.ghidra.service.function.FunctionResource;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Reference;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.TreeSet;

final class ControlFlowGraphQueries {
  private static final long NANOS_PER_MILLISECOND = 1_000_000L;
  private static final Comparator<OutgoingRef> OUTGOING_REF_ORDER =
      Comparator.comparing(OutgoingRef::from)
          .thenComparing(OutgoingRef::to)
          .thenComparing(OutgoingRef::type)
          .thenComparingInt(OutgoingRef::operandIndex);

  private final GhidraSession context;
  private final FunctionResolver resolver;

  ControlFlowGraphQueries(GhidraSession context, FunctionResolver resolver) {
    this.context = context;
    this.resolver = resolver;
  }

  ControlFlowGraphResource getControlFlowGraph(
      String rawEntry, String rawAddress, int maxInstructions, int timeoutMs) {
    Function function = resolveTargetFunction(rawEntry, rawAddress);
    int clampedMaxInstructions = clampMaxInstructions(maxInstructions);
    long startedNanos = System.nanoTime();
    long timeoutNanos = Math.max(1L, timeoutMs) * NANOS_PER_MILLISECOND;

    String entry = AddressUtil.canonicalAddress(function.getEntryPoint());
    String name = function.getName();
    String namespace = String.valueOf(function.getParentNamespace());
    String demangledName =
        CppSymbolNames.demangled(function.getProgram(), name, function.getEntryPoint());
    AddressSetView bodySet = function.getBody();
    if (function.isExternal() || bodySet == null || bodySet.isEmpty()) {
      return new ControlFlowGraphResource(
          entry, name, namespace, demangledName, null, false, 0, List.of(), List.of(), List.of(),
          null);
    }

    String bodyStart = AddressUtil.canonicalAddress(bodySet.getMinAddress());
    String bodyEnd = AddressUtil.canonicalAddress(bodySet.getMaxAddress());
    FunctionResource.Body body =
        new FunctionResource.Body(bodyStart, bodyEnd, bodySet.getNumAddresses());

    List<BodyInstruction> instructions = new ArrayList<>();
    String scannedStart = null;
    String scannedEnd = null;
    ScanProgress.StopReason stopReason = ScanProgress.StopReason.COMPLETED;

    InstructionIterator iterator =
        context.currentProgram().getListing().getInstructions(bodySet, true);
    while (iterator.hasNext()) {
      Instruction instruction = iterator.next();
      String address = AddressUtil.canonicalAddress(instruction.getAddress());
      if (scannedStart == null) scannedStart = address;
      scannedEnd = address;
      instructions.add(describeInstruction(instruction, address));

      if (elapsedNanos(startedNanos) >= timeoutNanos && iterator.hasNext()) {
        stopReason = ScanProgress.StopReason.TIMEOUT;
        break;
      }
      if (instructions.size() >= clampedMaxInstructions && iterator.hasNext()) {
        stopReason = ScanProgress.StopReason.LIMIT;
        break;
      }
    }

    if (instructions.isEmpty()) {
      ScanProgress emptyProgress =
          buildProgress(bodyStart, bodyEnd, scannedStart, scannedEnd, stopReason, startedNanos);
      return new ControlFlowGraphResource(
          entry,
          name,
          namespace,
          demangledName,
          body,
          false,
          0,
          List.of(),
          List.of(),
          List.of(),
          emptyProgress);
    }

    PartitionResult partitioned =
        partitionBlocks(instructions, startedNanos, timeoutNanos, stopReason);
    GraphPayload payload =
        buildGraphPayload(instructions, entry, partitioned.starts(), partitioned.targets());
    ScanProgress progress =
        buildProgress(
            bodyStart, bodyEnd, scannedStart, scannedEnd, partitioned.stopReason(), startedNanos);

    return new ControlFlowGraphResource(
        entry,
        name,
        namespace,
        demangledName,
        body,
        true,
        partitioned.unresolved(),
        payload.blocks(),
        payload.nodes(),
        payload.edges(),
        progress);
  }

  private Function resolveTargetFunction(String rawEntry, String rawAddress) {
    boolean hasEntry = rawEntry != null && !rawEntry.isBlank();
    boolean hasAddress = rawAddress != null && !rawAddress.isBlank();
    if (hasEntry == hasAddress) {
      throw new IllegalArgumentException("selector requires exactly one of entry or address");
    }
    if (hasEntry) {
      return resolver.resolveFunction(rawEntry);
    }
    Address parsed = context.parseAddress(rawAddress);
    FunctionManager manager = context.currentProgram().getFunctionManager();
    Function containing = manager.getFunctionContaining(parsed);
    if (containing != null) {
      return containing;
    }
    Function atAddress = manager.getFunctionAt(parsed);
    if (atAddress != null) {
      return atAddress;
    }
    throw new NoSuchElementException("no function contains address: " + rawAddress);
  }

  private BodyInstruction describeInstruction(Instruction instruction, String canonicalAddress) {
    int length = Math.max(1, instruction.getLength());
    String mnemonic = instruction.getMnemonicString();
    StringBuilder operands = new StringBuilder();
    for (int index = 0; index < instruction.getNumOperands(); index++) {
      if (index > 0) operands.append(", ");
      operands.append(instruction.getDefaultOperandRepresentation(index));
    }
    String line = (mnemonic + " " + operands).trim();
    String flowType = instruction.getFlowType().getName();
    String fallThrough = AddressUtil.canonicalAddress(instruction.getFallThrough());
    return new BodyInstruction(
        instruction.getAddress(), canonicalAddress, length, line, flowType, fallThrough);
  }

  private PartitionResult partitionBlocks(
      List<BodyInstruction> instructions,
      long startedNanos,
      long timeoutNanos,
      ScanProgress.StopReason initialReason) {
    Map<String, Integer> indexByAddress = new HashMap<>(instructions.size() * 2);
    for (int index = 0; index < instructions.size(); index++) {
      indexByAddress.putIfAbsent(instructions.get(index).address(), index);
    }

    List<List<TargetEdge>> targets = new ArrayList<>(instructions.size());
    TreeSet<Integer> leaders = new TreeSet<>();
    leaders.add(0);
    int unresolved = 0;
    ScanProgress.StopReason reason = initialReason;

    for (int index = 0; index < instructions.size(); index++) {
      BodyInstruction instruction = instructions.get(index);
      String flow = instruction.flowType();
      List<TargetEdge> outgoing = new ArrayList<>();

      if (flow.contains("JUMP") || flow.contains("BRANCH")) {
        if (reason != ScanProgress.StopReason.TIMEOUT
            && elapsedNanos(startedNanos) >= timeoutNanos) {
          reason = ScanProgress.StopReason.TIMEOUT;
        }
        if (reason != ScanProgress.StopReason.TIMEOUT) {
          for (OutgoingRef ref : branchReferencesFrom(instruction.rawAddress(), instruction.address())) {
            outgoing.add(new TargetEdge(ref.to(), ref.type()));
          }
        }
        if (outgoing.isEmpty()) {
          unresolved++;
        }
      }

      String fallThrough = instruction.fallThrough();
      if (fallThrough != null && !fallThrough.isEmpty()) {
        String label = flow.contains("CONDITIONAL") ? "Fall through" : "";
        outgoing.add(new TargetEdge(fallThrough, label));
      }

      boolean breaksFlow =
          flow.contains("JUMP")
              || flow.contains("BRANCH")
              || flow.contains("TERMINATOR")
              || flow.contains("RETURN")
              || fallThrough == null
              || fallThrough.isEmpty();
      if (breaksFlow) {
        if (index + 1 < instructions.size()) {
          leaders.add(index + 1);
        }
        for (TargetEdge edge : outgoing) {
          Integer targetIndex = indexByAddress.get(edge.to());
          if (targetIndex != null) {
            leaders.add(targetIndex);
          }
        }
      } else if (index + 1 < instructions.size()) {
        String nextAddress = instructions.get(index + 1).address();
        if (!fallThrough.equals(nextAddress)) {
          leaders.add(index + 1);
          Integer fallIndex = indexByAddress.get(fallThrough);
          if (fallIndex != null) {
            leaders.add(fallIndex);
          }
        }
      }
      targets.add(outgoing);
    }

    return new PartitionResult(List.copyOf(leaders), targets, unresolved, reason);
  }

  private List<OutgoingRef> branchReferencesFrom(Address rawFrom, String canonicalFrom) {
    List<OutgoingRef> matched = new ArrayList<>();
    for (Reference reference : context.references(rawFrom, false)) {
      String type = reference.getReferenceType().getName();
      if (!type.contains("JUMP") && !type.contains("BRANCH")) {
        continue;
      }
      String to =
          rawFrom.equals(reference.getToAddress())
              ? canonicalFrom
              : AddressUtil.canonicalAddress(reference.getToAddress());
      matched.add(new OutgoingRef(canonicalFrom, to, type, reference.getOperandIndex()));
    }
    matched.sort(OUTGOING_REF_ORDER);
    return matched;
  }

  private static GraphPayload buildGraphPayload(
      List<BodyInstruction> instructions,
      String entry,
      List<Integer> starts,
      List<List<TargetEdge>> targets) {
    List<BlockSlice> slices = new ArrayList<>(starts.size());
    Map<String, String> membership = new HashMap<>(instructions.size() * 2);

    for (int blockIndex = 0; blockIndex < starts.size(); blockIndex++) {
      int startIndex = starts.get(blockIndex);
      int endIndex =
          blockIndex + 1 < starts.size() ? starts.get(blockIndex + 1) : instructions.size();
      List<BodyInstruction> slice = instructions.subList(startIndex, endIndex);
      String blockId = "block:" + blockIndex;
      for (BodyInstruction instruction : slice) {
        membership.putIfAbsent(instruction.address(), blockId);
      }
      slices.add(new BlockSlice(blockId, endIndex - 1, slice));
    }

    List<NodeResource> nodes = new ArrayList<>(slices.size());
    List<BlockResource> blocks = new ArrayList<>(slices.size());
    for (BlockSlice slice : slices) {
      String firstAddress = slice.instructions().getFirst().address();
      List<String> lines = new ArrayList<>(slice.instructions().size());
      List<BlockInstructionResource> blockInstructions =
          new ArrayList<>(slice.instructions().size());
      for (BodyInstruction instruction : slice.instructions()) {
        lines.add(instruction.line());
        blockInstructions.add(
            new BlockInstructionResource(instruction.address(), instruction.length()));
      }
      nodes.add(new NodeResource(slice.blockId(), "block", firstAddress, entry, lines));
      blocks.add(new BlockResource(firstAddress, blockInstructions));
    }

    List<RawEdge> rawEdges = new ArrayList<>();
    Set<String> externalSeen = new HashSet<>();
    for (BlockSlice slice : slices) {
      for (TargetEdge target : targets.get(slice.lastIndex())) {
        String toId = membership.get(target.to());
        if (toId == null) {
          toId = "external:" + target.to();
          if (externalSeen.add(toId)) {
            nodes.add(new NodeResource(toId, "external", target.to(), null, null));
          }
        }
        rawEdges.add(new RawEdge(slice.blockId(), toId, target.label()));
      }
    }

    Set<String> branchSources = new HashSet<>();
    for (RawEdge rawEdge : rawEdges) {
      if (isConditionalLabel(rawEdge.label())) {
        branchSources.add(rawEdge.from());
      }
    }

    List<EdgeResource> edges = new ArrayList<>(rawEdges.size());
    for (RawEdge rawEdge : rawEdges) {
      String kind;
      if (isConditionalLabel(rawEdge.label())) {
        kind = "taken";
      } else if (("fall through".equalsIgnoreCase(rawEdge.label())
              || "fall-through".equalsIgnoreCase(rawEdge.label()))
          && branchSources.contains(rawEdge.from())) {
        kind = "fallthrough";
      } else {
        kind = "flow";
      }
      edges.add(new EdgeResource(rawEdge.from(), rawEdge.to(), rawEdge.label(), kind));
    }

    return new GraphPayload(blocks, nodes, edges);
  }

  private static boolean isConditionalLabel(String label) {
    return label.contains("CONDITIONAL") && !label.contains("UNCONDITIONAL");
  }

  private static int clampMaxInstructions(int maxInstructions) {
    if (maxInstructions <= 0) {
      return ControlFlowGraphResource.DEFAULT_MAX_INSTRUCTIONS;
    }
    return Math.max(
        ControlFlowGraphResource.MIN_MAX_INSTRUCTIONS,
        Math.min(maxInstructions, ControlFlowGraphResource.MAX_MAX_INSTRUCTIONS));
  }

  private static long elapsedNanos(long startedNanos) {
    return Math.max(0L, System.nanoTime() - startedNanos);
  }

  private static ScanProgress buildProgress(
      String requestedStart,
      String requestedEnd,
      String scannedStart,
      String scannedEnd,
      ScanProgress.StopReason stopReason,
      long startedNanos) {
    long elapsedMillis = elapsedNanos(startedNanos) / NANOS_PER_MILLISECOND;
    boolean complete = stopReason == ScanProgress.StopReason.COMPLETED;
    return new ScanProgress(
        ScanProgress.Kind.ADDRESS,
        requestedStart,
        requestedEnd,
        scannedStart,
        scannedEnd,
        complete,
        stopReason,
        elapsedMillis);
  }

  private record BodyInstruction(
      Address rawAddress,
      String address,
      int length,
      String line,
      String flowType,
      String fallThrough) {}

  private record OutgoingRef(String from, String to, String type, int operandIndex) {}

  private record TargetEdge(String to, String label) {}

  private record PartitionResult(
      List<Integer> starts,
      List<List<TargetEdge>> targets,
      int unresolved,
      ScanProgress.StopReason stopReason) {}

  private record BlockSlice(
      String blockId, int lastIndex, List<BodyInstruction> instructions) {}

  private record RawEdge(String from, String to, String label) {}

  private record GraphPayload(
      List<BlockResource> blocks, List<NodeResource> nodes, List<EdgeResource> edges) {}
}
