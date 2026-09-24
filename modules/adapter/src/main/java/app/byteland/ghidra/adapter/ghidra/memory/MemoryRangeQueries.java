package app.byteland.ghidra.adapter.ghidra.memory;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.memory.MemoryResource;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryAccessException;

final class MemoryRangeQueries {
  private final GhidraSession context;
  private final int maxRangeLength;

  MemoryRangeQueries(GhidraSession context, int maxRangeLength) {
    this.context = context;
    this.maxRangeLength = maxRangeLength;
  }

  MemoryResource readMemoryRange(String startRaw, int length, ByteSequence.Encoding encoding) {
    if (length < 1 || length > maxRangeLength) {
      throw new IllegalArgumentException("length must be in 1.." + maxRangeLength);
    }
    Address start = parseAddress(startRaw);
    byte[] bytes;
    try {
      bytes = readBytes(start, length);
    } catch (MemoryAccessException ex) {
      throw new IllegalArgumentException("unable to read memory range: " + ex.getMessage(), ex);
    }
    String encodingLower = encoding.name().toLowerCase(java.util.Locale.ROOT);
    String encoded = MemoryEncoding.encodeBytes(bytes, encodingLower, bytes.length);
    ByteSequence.Encoding byteEncoding =
        "base64".equals(encodingLower) ? ByteSequence.Encoding.BASE64 : ByteSequence.Encoding.HEX;
    return new MemoryResource(
        AddressUtil.canonicalAddress(start), new ByteSequence(byteEncoding, encoded, bytes.length));
  }

  private Address parseAddress(String rawAddress) {
    return context.parseAddress(rawAddress);
  }

  private byte[] readBytes(Address start, int length) throws MemoryAccessException {
    return context.script().getBytes(start, length);
  }
}
