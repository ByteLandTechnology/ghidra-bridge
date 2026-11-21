package app.byteland.ghidra.service.memory;

import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.Page;
import java.util.Objects;

/**
 * Reads memory blocks, searches initialized bytes, reads byte ranges, and patches program bytes.
 */
public interface MemoryService {
  int MAX_RANGE_LENGTH = 65_536;
  int MAX_SEARCH_PATTERN_BYTES = 4_096;

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
   * Target specification for bounded memory search.
   */
  sealed interface SearchTarget permits HexPattern, MaskedBytes, EncodedText {}

  /**
   * Hex byte pattern with optional wildcard nibbles or bytes.
   */
  record HexPattern(String pattern) implements SearchTarget {
    public HexPattern {
      if (pattern == null || pattern.isBlank()) {
        throw new IllegalArgumentException("pattern is required");
      }
    }
  }

  /**
   * Hex byte sequence paired with an optional hex bitmask of equal byte length.
   */
  record MaskedBytes(String bytesHex, String maskHex) implements SearchTarget {
    public MaskedBytes {
      if (bytesHex == null || bytesHex.isBlank()) {
        throw new IllegalArgumentException("bytes is required");
      }
    }
  }

  /**
   * Text string encoded in a specified character encoding.
   */
  record EncodedText(String text, String encoding, boolean caseSensitive) implements SearchTarget {
    public EncodedText {
      if (text == null || text.isEmpty()) {
        throw new IllegalArgumentException("text is required");
      }
      encoding = encoding == null || encoding.isBlank() ? "utf-8" : encoding;
    }
  }

  /**
   * Bounded scan query for initialized memory search.
   */
  record MemorySearchQuery(
      AddressScanOptions scan, SearchTarget target, int limit, String cursor) {
    public MemorySearchQuery {
      Objects.requireNonNull(scan, "scan");
      Objects.requireNonNull(target, "target");
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
   * Returns memory block metadata by block name.
   */
  MemoryBlockResource getMemoryBlockByName(String rawName);

  /**
   * Reads raw bytes from a specified memory range.
   */
  MemoryResource readMemoryRange(String startRaw, int length, ByteSequence.Encoding encoding);

  /**
   * Searches initialized memory blocks for byte sequences that match the query.
   */
  default Page<MemorySearchMatchResource> searchMemory(MemorySearchQuery query) {
    throw new UnsupportedOperationException("searchMemory is not implemented");
  }

  /**
   * Patches program memory with the specified byte sequence.
   */
  void patchMemory(String startRaw, ByteSequence bytes);
}
