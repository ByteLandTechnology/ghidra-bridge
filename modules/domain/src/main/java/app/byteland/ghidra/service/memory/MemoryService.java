package app.byteland.ghidra.service.memory;

import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.Page;

/**
 * Reads memory blocks, reads byte ranges, and patches program bytes.
 */
public interface MemoryService {
  /** Maximum number of bytes that can be read in a single memory range request. */
  int MAX_RANGE_LENGTH = 65_536;

  /**
   * Query parameters for memory block filters.
   *
   * @param limit maximum items per page ({@code 1..1000})
   * @param cursor pagination cursor, or {@code null}
   * @param execute optional executable permission filter
   * @param write optional writable permission filter
   * @param read optional readable permission filter
   * @param name optional block name substring or exact match filter
   */
  record MemoryBlockQuery(
      int limit, String cursor, Boolean execute, Boolean write, Boolean read, String name) {
    /** Validates that {@code limit} is within {@code 1..1000}. */
    public MemoryBlockQuery {
      if (limit < 1 || limit > 1000) throw new IllegalArgumentException("limit must be in 1..1000");
    }
  }

  /**
   * Returns one page of memory blocks.
   *
   * @param query memory block filter criteria
   * @return page of matching memory blocks
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
   * @param length byte count to read
   * @param encoding wire encoding format for the returned bytes
   * @return memory byte slice resource
   */
  MemoryResource readMemoryRange(String startRaw, int length, ByteSequence.Encoding encoding);

  /**
   * Patches program memory with the specified byte sequence.
   *
   * @param startRaw start address to overwrite
   * @param bytes replacement byte sequence
   */
  void patchMemory(String startRaw, ByteSequence bytes);
}
