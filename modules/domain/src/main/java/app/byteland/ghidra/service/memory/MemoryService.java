package app.byteland.ghidra.service.memory;

import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.Page;

/**
 * Reads memory blocks, reads byte ranges, and patches program bytes.
 */
public interface MemoryService {
  int MAX_RANGE_LENGTH = 65_536;

  /**
   * Query parameters for memory block filters.
   */
  record MemoryBlockQuery(
      int limit, String cursor, Boolean execute, Boolean write, Boolean read, String name) {
    public MemoryBlockQuery {
      if (limit < 1 || limit > 1000) throw new IllegalArgumentException("limit must be in 1..1000");
    }
  }

  /**
   * Parameters for a new memory block.
   */
  record MemoryBlockCreateRequest(
      String name,
      String start,
      long length,
      boolean initialized,
      Integer fillByte,
      ByteSequence bytes,
      boolean read,
      boolean write,
      boolean execute,
      boolean isVolatile,
      boolean overlay,
      String comment) {
    public MemoryBlockCreateRequest {
      if (name == null || name.isBlank()) {
        throw new IllegalArgumentException("name must not be blank");
      }
      if (start == null || start.isBlank()) {
        throw new IllegalArgumentException("start must not be blank");
      }
      if (length < 1) {
        throw new IllegalArgumentException("length must be positive");
      }
      if (fillByte != null && (fillByte < 0 || fillByte > 255)) {
        throw new IllegalArgumentException("fillByte must be in 0..255");
      }
    }
  }

  /**
   * Returns one page of memory blocks.
   */
  Page<MemoryBlockResource> listMemoryBlocks(MemoryBlockQuery query);

  /**
   * Returns memory block metadata by block name.
   */
  MemoryBlockResource getMemoryBlockByName(String rawName);

  /**
   * Creates one memory block and returns its metadata.
   */
  MemoryBlockResource createMemoryBlock(MemoryBlockCreateRequest request);

  /**
   * Reads raw bytes from a specified memory range.
   */
  MemoryResource readMemoryRange(String startRaw, int length, ByteSequence.Encoding encoding);

  /**
   * Patches program memory with the specified byte sequence.
   */
  void patchMemory(String startRaw, ByteSequence bytes);
}
