package app.byteland.ghidra.service.memory;

import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.Page;

/**
 * Reads memory blocks, reads byte ranges, and patches program bytes.
 */
public interface MemoryService {
  /** Maximum byte length allowed for one memory read or patch operation. */
  int MAX_RANGE_LENGTH = 65_536;

  /**
   * Query parameters for memory block filters.
   *
   * @param limit maximum items to return in 1..1000
   * @param cursor optional pagination cursor
   * @param execute optional executable permission filter
   * @param write optional writable permission filter
   * @param read optional readable permission filter
   * @param name optional substring name filter
   */
  record MemoryBlockQuery(
      int limit, String cursor, Boolean execute, Boolean write, Boolean read, String name) {
    /** Validates the page size limit bounds. */
    public MemoryBlockQuery {
      if (limit < 1 || limit > 1000) throw new IllegalArgumentException("limit must be in 1..1000");
    }
  }

  /**
   * Returns one page of memory blocks.
   *
   * @param query permission, name, and pagination filters
   * @return page of memory block resources
   */
  Page<MemoryBlockResource> listMemoryBlocks(MemoryBlockQuery query);

  /**
   * Returns memory block metadata by block name.
   *
   * @param rawName memory block name
   * @return memory block resource
   */
  MemoryBlockResource getMemoryBlockByName(String rawName);

  /**
   * Reads raw bytes from a specified memory range.
   *
   * @param startRaw range start address
   * @param length number of bytes to read
   * @param encoding output byte sequence encoding
   * @return encoded memory range resource
   */
  MemoryResource readMemoryRange(String startRaw, int length, ByteSequence.Encoding encoding);

  /**
   * Patches program memory with the specified byte sequence.
   *
   * @param startRaw destination start address
   * @param bytes byte sequence to write
   */
  void patchMemory(String startRaw, ByteSequence bytes);
}
