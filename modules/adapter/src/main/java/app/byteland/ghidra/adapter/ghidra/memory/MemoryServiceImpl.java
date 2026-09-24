package app.byteland.ghidra.adapter.ghidra.memory;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.memory.MemoryBlockResource;
import app.byteland.ghidra.service.memory.MemoryResource;
import app.byteland.ghidra.service.memory.MemoryService;

public final class MemoryServiceImpl implements MemoryService {
  private final MemoryBlockQueries memoryBlockQueries;
  private final MemoryRangeQueries memoryRangeQueries;
  private final MemoryMutations memoryMutations;

  public MemoryServiceImpl(GhidraSession context) {
    this.memoryBlockQueries = new MemoryBlockQueries(context);
    this.memoryRangeQueries = new MemoryRangeQueries(context, MemoryService.MAX_RANGE_LENGTH);
    this.memoryMutations = new MemoryMutations(context);
  }

  @Override
  public Page<MemoryBlockResource> listMemoryBlocks(MemoryBlockQuery query) {
    return memoryBlockQueries.listMemoryBlocks(
        query.limit(), query.cursor(), query.execute(), query.write(), query.read(), query.name());
  }

  @Override
  public MemoryBlockResource getMemoryBlockByName(String rawName) {
    return memoryBlockQueries.getMemoryBlockByName(rawName);
  }

  @Override
  public MemoryResource readMemoryRange(
      String startRaw, int length, ByteSequence.Encoding encoding) {
    return memoryRangeQueries.readMemoryRange(startRaw, length, encoding);
  }

  @Override
  public void patchMemory(String startRaw, ByteSequence bytes) {
    memoryMutations.patchMemory(startRaw, bytes);
  }
}
