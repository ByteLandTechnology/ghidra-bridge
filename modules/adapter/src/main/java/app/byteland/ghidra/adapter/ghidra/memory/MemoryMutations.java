package app.byteland.ghidra.adapter.ghidra.memory;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.ByteSequence;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryAccessException;

final class MemoryMutations {
  private final GhidraSession context;

  MemoryMutations(GhidraSession context) {
    this.context = context;
  }

  void patchMemory(String startRaw, ByteSequence sequence) {
    Address start = parseAddress(startRaw);
    byte[] bytes =
        MemoryEncoding.decodeBytes(
            sequence.data(), sequence.encoding().name().toLowerCase(java.util.Locale.ROOT));
    writeBytes(start, bytes);
  }

  private Address parseAddress(String rawAddress) {
    return context.parseAddress(rawAddress);
  }

  private void writeBytes(Address start, byte[] bytes) {
    try {
      context.script().setBytes(start, bytes);
    } catch (MemoryAccessException ex) {
      throw new IllegalArgumentException("unable to write memory: " + ex.getMessage(), ex);
    }
  }
}
