package app.byteland.ghidra.adapter.ghidra.memory;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.memory.MemoryBlockResource;
import ghidra.program.model.mem.MemoryBlock;
import java.util.List;
import java.util.Locale;
import java.util.NoSuchElementException;

final class MemoryBlockQueries {
  private final GhidraSession context;

  MemoryBlockQueries(GhidraSession context) {
    this.context = context;
  }

  Page<MemoryBlockResource> listMemoryBlocks(
      int limit,
      String cursor,
      Boolean execute,
      Boolean write,
      Boolean read,
      String nameFilterRaw) {
    String normalizedName = MemoryPageSupport.normalizeNameFilter(nameFilterRaw);
    List<MemoryBlock> ordered =
        java.util.Arrays.stream(memoryBlocks())
            .filter(
                block ->
                    MemoryPageSupport.matchesFilters(block, execute, write, read, normalizedName))
            .sorted(java.util.Comparator.comparing(MemoryBlock::getName))
            .toList();
    Page<MemoryBlock> page = Page.paginate(ordered, limit, cursor, MemoryBlock::getName);
    List<MemoryBlockResource> blocks =
        page.items().stream().map(MemoryBlockQueries::describeMemoryBlock).toList();
    return Page.of(blocks, page.limit(), page.nextCursor());
  }

  MemoryBlockResource getMemoryBlockByName(String rawName) {
    MemoryBlock block = context.script().getMemoryBlock(rawName);
    if (block == null) {
      throw new NoSuchElementException("memory block not found: " + rawName);
    }
    return describeMemoryBlock(block);
  }

  private static MemoryBlockResource describeMemoryBlock(MemoryBlock block) {
    return new MemoryBlockResource(
        block.getName(),
        AddressUtil.canonicalAddress(block.getStart()),
        AddressUtil.canonicalAddress(block.getEnd()),
        block.getSize(),
        block.isRead(),
        block.isWrite(),
        block.isExecute(),
        block.isInitialized(),
        block.isVolatile(),
        block.isOverlay(),
        memoryBlockKind(block),
        block.getComment());
  }

  private static MemoryBlockResource.Kind memoryBlockKind(MemoryBlock block) {
    String kind = block.getType().toString().toUpperCase(Locale.ROOT).replace(' ', '_');
    return switch (kind) {
      case "DEFAULT" -> MemoryBlockResource.Kind.DEFAULT;
      case "BIT_MAPPED" -> MemoryBlockResource.Kind.BIT_MAPPED;
      case "BYTE_MAPPED" -> MemoryBlockResource.Kind.BYTE_MAPPED;
      default -> MemoryBlockResource.Kind.OTHER;
    };
  }

  private MemoryBlock[] memoryBlocks() {
    return context.script().getMemoryBlocks();
  }
}
