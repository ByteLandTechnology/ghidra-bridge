package app.byteland.ghidra.service.memory;

import app.byteland.ghidra.service.ByteSequence;
import java.util.Objects;

/**
 * Describes one byte sequence match in an initialized memory block.
 */
public record MemorySearchMatchResource(
    String address, int length, ByteSequence bytes, String blockName) {
  public MemorySearchMatchResource {
    Objects.requireNonNull(address, "address");
    if (length < 1) {
      throw new IllegalArgumentException("length must be positive");
    }
    Objects.requireNonNull(bytes, "bytes");
    Objects.requireNonNull(blockName, "blockName");
  }
}
