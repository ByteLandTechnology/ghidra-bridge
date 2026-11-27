package app.byteland.ghidra.service.memory;

import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.Page;

/**
 * Reads memory blocks, searches byte patterns, reads byte ranges, and patches program bytes.
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
   * Query parameters for wildcard byte pattern search.
   */
  record MemoryFindQuery(AddressScanOptions scan, String pattern, int limit, String cursor) {
    public MemoryFindQuery {
      if (scan == null) throw new IllegalArgumentException("scan is required");
      if (pattern == null || pattern.isBlank()) {
        throw new IllegalArgumentException("pattern is required");
      }
      if (limit < 1 || limit > Page.MAX_LIMIT) {
        throw new IllegalArgumentException("limit must be in 1.." + Page.MAX_LIMIT);
      }
    }
  }

  /**
   * Returns one page of memory blocks.
   */
  Page<MemoryBlockResource> listMemoryBlocks(MemoryBlockQuery query);

  /**
   * Returns one page of byte pattern matches in initialized memory.
   */
  Page<MemoryMatchResource> findMemory(MemoryFindQuery query);

  /**
   * Returns memory block metadata by block name.
   */
  MemoryBlockResource getMemoryBlockByName(String rawName);

  /**
   * Reads raw bytes from a specified memory range.
   */
  MemoryResource readMemoryRange(String startRaw, int length, ByteSequence.Encoding encoding);

  /**
   * Patches program memory with the specified byte sequence.
   */
  void patchMemory(String startRaw, ByteSequence bytes);
}
