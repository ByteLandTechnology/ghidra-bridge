package app.byteland.ghidra.adapter.ghidra.listing;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraDataTypeReferences;
import app.byteland.ghidra.adapter.ghidra.listing.ListingStringQueries.StreamItem;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.DefinedStringIterator;

/**
 * Streams defined strings in address order across an initialized address range.
 */
final class DefinedStringStream {
  private final Program program;
  private final Address effectiveStart;
  private final Address iterEnd;
  private final DefinedStringIterator iterator;
  private final boolean bigEndian;
  private StreamItem nextItem;
  private boolean exhausted;

  DefinedStringStream(Program program, Address effectiveStart, Address iterEnd) {
    this.program = program;
    this.effectiveStart = effectiveStart;
    this.iterEnd = iterEnd;
    this.bigEndian = program.getLanguage().isBigEndian();
    Data containing = program.getListing().getDefinedDataContaining(effectiveStart);
    Address seedStart =
        containing != null && containing.getMinAddress().compareTo(effectiveStart) < 0
            ? containing.getMinAddress()
            : effectiveStart;
    this.iterator =
        DefinedStringIterator.forProgram(program, new AddressSet(seedStart, iterEnd));
  }

  StreamItem peek() {
    if (nextItem == null && !exhausted) {
      nextItem = advance();
      if (nextItem == null) {
        exhausted = true;
      }
    }
    return nextItem;
  }

  StreamItem take() {
    StreamItem item = peek();
    nextItem = null;
    return item;
  }

  private StreamItem advance() {
    Memory memory = program.getMemory();
    while (iterator.hasNext()) {
      Data data = iterator.next();
      Address address = data.getAddress();
      if (address.compareTo(effectiveStart) < 0) {
        continue;
      }
      if (address.compareTo(iterEnd) > 0) {
        return null;
      }
      MemoryBlock block = memory.getBlock(address);
      if (block == null || !block.isInitialized()) {
        continue;
      }
      StringDataInstance instance = StringDataInstance.getStringDataInstance(data);
      if (instance == null || instance == StringDataInstance.NULL_INSTANCE) {
        continue;
      }
      String value = instance.getStringValue();
      if (value == null) {
        continue;
      }
      String encoding = normalizeDefinedCharset(instance.getCharsetName(), bigEndian);
      String canonical = AddressUtil.canonicalAddress(address);
      DataType dataType = data.getDataType();
      return new StreamItem(
          address,
          canonical,
          canonical,
          data.getLength(),
          value,
          encoding,
          true,
          () -> GhidraDataTypeReferences.toReference(dataType));
    }
    return null;
  }

  static String normalizeDefinedCharset(String rawCharset, boolean bigEndian) {
    if (rawCharset == null || rawCharset.isBlank()) {
      return StringDataInstance.DEFAULT_CHARSET_NAME;
    }
    if ("UTF-16".equalsIgnoreCase(rawCharset)) {
      return bigEndian ? "UTF-16BE" : "UTF-16LE";
    }
    if ("UTF-32".equalsIgnoreCase(rawCharset)) {
      return bigEndian ? "UTF-32BE" : "UTF-32LE";
    }
    return rawCharset;
  }
}
