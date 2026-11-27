package app.byteland.ghidra.service.memory;

import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.Page;

/**
 * Reads memory blocks, reads byte ranges, and patches program bytes.
 */
public interface MemoryService {
  /** Maximum byte count that one {@link #readMemoryRange} call accepts. */
  int MAX_RANGE_LENGTH = 65_536;

  /**
   * Query parameters for memory block filters.
   *
   * @param limit maximum blocks to return in {@code 1..1000}
   * @param cursor optional pagination cursor
   * @param execute optional executable-permission filter
   * @param write optional writable-permission filter
   * @param read optional readable-permission filter
   * @param name optional case-insensitive block name text filter
   */
  record MemoryBlockQuery(
      int limit, String cursor, Boolean execute, Boolean write, Boolean read, String name) {
    /** Validates page limit bounds. */
    public MemoryBlockQuery {
      if (limit < 1 || limit > 1000) throw new IllegalArgumentException("limit must be in 1..1000");
    }
  }

  /**
   * Returns one page of memory blocks.
   *
   * @param query block filters and pagination options
   * @return page of memory block resources
   */
  Page<MemoryBlockResource> listMemoryBlocks(MemoryBlockQuery query);

  /**
   * Returns memory block metadata by block name.
   *
   * @param rawName exact memory block name
   * @return memory block resource
   */
  MemoryBlockResource getMemoryBlockByName(String rawName);

  /**
   * Reads raw bytes from a specified memory range.
   *
   * @param startRaw range start address
   * @param length byte count in {@code 1..MAX_RANGE_LENGTH}
   * @param encoding desired wire byte encoding
   * @return memory range resource
   */
  MemoryResource readMemoryRange(String startRaw, int length, ByteSequence.Encoding encoding);

  /**
   * Patches program memory with the specified byte sequence.
   *
   * @param startRaw patch start address
   * @param bytes replacement byte sequence
   */
  void patchMemory(String startRaw, ByteSequence bytes);
}
