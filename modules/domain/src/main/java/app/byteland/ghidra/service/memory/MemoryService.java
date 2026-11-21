package app.byteland.ghidra.service.memory;

import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.Page;

/**
 * Reads memory blocks, reads byte ranges, and patches program bytes.
 */
public interface MemoryService {
  /** Maximum byte count allowed in a single memory read request. */
  int MAX_RANGE_LENGTH = 65_536;

  /**
   * Query parameters for memory block filters.
   *
   * @param limit maximum items per page
   * @param cursor optional pagination cursor
   * @param execute optional execute permission filter
   * @param write optional write permission filter
   * @param read optional read permission filter
   * @param name optional block name substring filter
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
   * @param query memory block filter and pagination options
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
   * @param startRaw start memory address
   * @param length number of bytes to read
   * @param encoding wire byte encoding format
   * @return memory range resource with encoded bytes
   */
  MemoryResource readMemoryRange(String startRaw, int length, ByteSequence.Encoding encoding);

  /**
   * Patches program memory with the specified byte sequence.
   *
   * @param startRaw start memory address
   * @param bytes byte sequence to write
   */
  void patchMemory(String startRaw, ByteSequence bytes);
}
