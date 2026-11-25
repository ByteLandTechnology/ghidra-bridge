package app.byteland.ghidra.adapter.ghidra.memory;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.TransactionExecutionException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
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
    if (bytes.length > 0) {
      Address end;
      try {
        end = bytes.length == 1 ? start : start.addNoWrap(bytes.length - 1L);
      } catch (AddressOverflowException overflow) {
        end = start.getAddressSpace().getMaxAddress();
      }
      context.recordMutatedRange(start, end);
    }
  }

  private Address parseAddress(String rawAddress) {
    return context.parseAddress(rawAddress);
  }

  private void writeBytes(Address start, byte[] bytes) {
    try {
      context.script().setBytes(start, bytes);
    } catch (MemoryAccessException ex) {
      throw new TransactionExecutionException("unable to write memory: " + ex.getMessage(), ex);
    }
  }
}
