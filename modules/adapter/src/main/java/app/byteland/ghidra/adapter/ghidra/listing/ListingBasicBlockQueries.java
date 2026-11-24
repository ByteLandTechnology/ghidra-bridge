package app.byteland.ghidra.adapter.ghidra.listing;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.scan.BoundedAddressScan;
import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.listing.BasicBlockResource;
import app.byteland.ghidra.service.listing.BasicBlockResource.FlowEdge;
import app.byteland.ghidra.service.listing.BasicBlockResource.InstructionSummary;
import app.byteland.ghidra.service.listing.FlowOverrideScope;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitorAdapter;
import java.util.ArrayList;
import java.util.List;

final class ListingBasicBlockQueries {
  private static final long NANOS_PER_MILLISECOND = 1_000_000L;

  private final GhidraSession context;
  private final ListingFlowOverrideScopes scopes;

  ListingBasicBlockQueries(GhidraSession context, ListingFlowOverrideScopes scopes) {
    this.context = context;
    this.scopes = scopes;
  }

  Page<BasicBlockResource> listBasicBlocks(
      FlowOverrideScope selected,
      AddressScanOptions options,
      int maxEdges,
      int limit,
      String cursorRaw) {
    if (maxEdges < 1 || maxEdges > BasicBlockResource.MAX_EDGES) {
      throw new IllegalArgumentException(
          "maxEdges must be in 1.." + BasicBlockResource.MAX_EDGES);
    }
    int normalizedLimit = Page.clampLimit(limit);
    ListingFlowOverrideScopes.ResolvedScope scope = scopes.resolve(selected);
    AddressSetView scopeAddresses = scope.addresses();
    Address cursor = resolveCursor(cursorRaw, scopeAddresses);

    if (scopeAddresses.isEmpty()) {
      return BoundedAddressScan.<BasicBlockResource>start(
              normalizedLimit, options.timeoutMs(), null, null)
          .finish();
    }

    String requestedStart = AddressUtil.canonicalAddress(scopeAddresses.getMinAddress());
    String requestedEnd = AddressUtil.canonicalAddress(scopeAddresses.getMaxAddress());
    BoundedAddressScan<BasicBlockResource> scan =
        BoundedAddressScan.start(
            normalizedLimit, options.timeoutMs(), requestedStart, requestedEnd);
    long deadlineNanos = System.nanoTime() + options.timeoutMs() * NANOS_PER_MILLISECOND;
    DeadlineMonitor monitor = new DeadlineMonitor(deadlineNanos);

    AddressSet searchAddresses = new AddressSet(scopeAddresses);
    if (cursor != null
        && cursor.getAddressSpace().equals(searchAddresses.getMinAddress().getAddressSpace())
        && cursor.compareTo(searchAddresses.getMinAddress()) > 0) {
      Address previous = cursor.previous();
      if (previous != null) {
        searchAddresses.delete(searchAddresses.getMinAddress(), previous);
      }
    }

    Program program = context.currentProgram();
    Listing listing = program.getListing();
    BasicBlockModel model = new BasicBlockModel(program);
    int totalEdges = 0;

    try {
      CodeBlockIterator blocks = model.getCodeBlocksContaining(searchAddresses, monitor);
      while (blocks.hasNext()) {
        if (monitor.isCancelled()) {
          scan.timeout();
          break;
        }
        CodeBlock block = blocks.next();
        AddressSet blockAddresses = block.intersect(scopeAddresses);
        if (blockAddresses.isEmpty()) continue;

        List<Instruction> rawInstructions = new ArrayList<>();
        for (Instruction instruction : listing.getInstructions(blockAddresses, true)) {
          rawInstructions.add(instruction);
        }
        if (rawInstructions.isEmpty()) continue;

        Instruction firstInstruction = rawInstructions.getFirst();
        Instruction lastInstruction = rawInstructions.getLast();
        Address startAddress = firstInstruction.getAddress();
        if (cursor != null && startAddress.compareTo(cursor) <= 0) {
          continue;
        }

        List<InstructionSummary> summaries = new ArrayList<>(rawInstructions.size());
        long byteLength = 0;
        for (Instruction instruction : rawInstructions) {
          summaries.add(toSummary(instruction));
          byteLength += instruction.getLength();
        }

        int edgeBudget = Math.max(0, maxEdges - totalEdges);
        BlockDestinations collected =
            collectDestinations(block, blockAddresses, lastInstruction, edgeBudget, monitor);
        totalEdges += collected.edges().size();

        String startText = AddressUtil.canonicalAddress(startAddress);
        String endText = AddressUtil.canonicalAddress(lastInstruction.getMaxAddress());
        BasicBlockResource resource =
            new BasicBlockResource(
                startText,
                endText,
                byteLength,
                lastInstruction.getFlowType().getName(),
                collected.unresolvedJump(),
                collected.edgesLimited(),
                summaries,
                collected.edges());
        scan.visit(startText, startText, resource);
        if (scan.stopped()) break;
        if (totalEdges >= maxEdges && blocks.hasNext()) {
          scan.reachLimit();
          break;
        }
      }
    } catch (CancelledException cancelled) {
      scan.timeout();
    }

    return scan.finish();
  }

  private Address resolveCursor(String cursorRaw, AddressSetView scopeAddresses) {
    if (cursorRaw == null || cursorRaw.isBlank()) {
      return null;
    }
    Address cursor = context.parseAddress(cursorRaw);
    if (!scopeAddresses.contains(cursor)) {
      throw new IllegalArgumentException("cursor must be inside the selected scope");
    }
    return cursor;
  }

  private static BlockDestinations collectDestinations(
      CodeBlock block,
      AddressSet blockAddresses,
      Instruction lastInstruction,
      int edgeBudget,
      DeadlineMonitor monitor)
      throws CancelledException {
    List<FlowEdge> edges = new ArrayList<>();
    boolean edgesLimited = false;
    boolean hasNonFallthroughDest = false;
    boolean truncatedTail = blockAddresses.getMaxAddress().compareTo(block.getMaxAddress()) < 0;

    CodeBlockReferenceIterator destinations = block.getDestinations(monitor);
    while (destinations.hasNext()) {
      monitor.checkCancelled();
      CodeBlockReference reference = destinations.next();
      FlowType flowType = reference.getFlowType();
      if (flowType.isCall()) continue;
      Address referent = reference.getReferent();
      if (referent == null || !blockAddresses.contains(referent)) continue;
      if (!RefType.FALL_THROUGH.equals(flowType)) {
        hasNonFallthroughDest = true;
      }
      if (edges.size() >= edgeBudget) {
        edgesLimited = true;
        continue;
      }
      edges.add(
          new FlowEdge(
              AddressUtil.canonicalAddress(referent),
              AddressUtil.canonicalAddress(reference.getDestinationAddress()),
              flowType.getName()));
    }

    if (truncatedTail && lastInstruction.getFallThrough() != null) {
      String from = AddressUtil.canonicalAddress(lastInstruction.getAddress());
      String to = AddressUtil.canonicalAddress(lastInstruction.getFallThrough());
      boolean alreadyPresent =
          edges.stream()
              .anyMatch(
                  edge ->
                      edge.from().equals(from)
                          && edge.to().equals(to)
                          && RefType.FALL_THROUGH.getName().equals(edge.type()));
      if (!alreadyPresent) {
        if (edges.size() >= edgeBudget) {
          edgesLimited = true;
        } else {
          edges.add(new FlowEdge(from, to, RefType.FALL_THROUGH.getName()));
        }
      }
    }

    boolean unresolvedJump =
        !truncatedTail && lastInstruction.getFlowType().isJump() && !hasNonFallthroughDest;
    return new BlockDestinations(List.copyOf(edges), edgesLimited, unresolvedJump);
  }

  private static InstructionSummary toSummary(Instruction instruction) {
    List<String> operands = new ArrayList<>(instruction.getNumOperands());
    for (int index = 0; index < instruction.getNumOperands(); index++) {
      operands.add(String.valueOf(instruction.getDefaultOperandRepresentation(index)));
    }
    return new InstructionSummary(
        AddressUtil.canonicalAddress(instruction.getAddress()),
        instruction.getLength(),
        instruction.getMnemonicString(),
        operands,
        instruction.getFlowType().getName(),
        AddressUtil.canonicalAddress(instruction.getFallThrough()));
  }

  private record BlockDestinations(
      List<FlowEdge> edges, boolean edgesLimited, boolean unresolvedJump) {}

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

    @Override
    public void checkCancelled() throws CancelledException {
      if (isCancelled()) {
        throw new CancelledException();
      }
    }
  }
}
