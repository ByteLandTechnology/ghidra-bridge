package app.byteland.ghidra.adapter.ghidra.listing;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.listing.CandidateStringDecoders.CandidateMatch;
import app.byteland.ghidra.adapter.ghidra.listing.ListingStringQueries.StreamItem;
import app.byteland.ghidra.adapter.ghidra.scan.BoundedAddressScan;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.listing.StringResource;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;

/**
 * Scans undefined initialized memory gaps for candidate strings in address order.
 */
final class CandidateStringScanner {
  private static final int READ_BUFFER_BYTES = 65_536;
  private static final int REFILL_WATERMARK_BYTES = 8_192;
  private static final int TIMEOUT_CHECK_BYTES = 4_096;

  private final Listing listing;
  private final Memory memory;
  private final Address rangeStart;
  private final Address iterEnd;
  private final String initialCursor;
  private final int minCandidateLength;
  private final boolean bigEndian;
  private final BoundedAddressScan<StringResource> scan;
  private final AddressRangeIterator initRanges;
  private final byte[] buffer = new byte[READ_BUFFER_BYTES];

  private Address currentRangeMax;
  private Address gapCursor;
  private Address activeGapEnd;
  private Address bufferBase;
  private int bufferLen;
  private int bufferPos;
  private int lastTimeoutCheckPos;
  private StreamItem nextItem;
  private boolean exhausted;

  CandidateStringScanner(
      Program program,
      Address rangeStart,
      Address effectiveStart,
      Address iterEnd,
      String initialCursor,
      int minCandidateLength,
      BoundedAddressScan<StringResource> scan) {
    this.listing = program.getListing();
    this.memory = program.getMemory();
    this.rangeStart = rangeStart;
    this.iterEnd = iterEnd;
    this.initialCursor = initialCursor;
    this.minCandidateLength = minCandidateLength;
    this.bigEndian = program.getLanguage().isBigEndian();
    this.scan = scan;
    AddressSetView initialized =
        memory.getAllInitializedAddressSet().intersect(new AddressSet(effectiveStart, iterEnd));
    this.initRanges = initialized.getAddressRanges();
  }

  StreamItem peekUpTo(Address limit) {
    if (nextItem != null) {
      return nextItem.address().compareTo(limit) <= 0 ? nextItem : null;
    }
    if (!exhausted && !scan.stopped()) {
      nextItem = advance(limit);
    }
    if (nextItem != null && nextItem.address().compareTo(limit) <= 0) {
      return nextItem;
    }
    return null;
  }

  StreamItem take() {
    StreamItem item = nextItem;
    nextItem = null;
    return item;
  }

  private StreamItem advance(Address limit) {
    while (!scan.stopped() && !exhausted) {
      if (!fillBuffer(limit)) {
        return null;
      }
      while (bufferPos < bufferLen) {
        Address candidateStart = advanceExact(bufferBase, bufferPos);
        if (candidateStart.compareTo(iterEnd) > 0) {
          exhausted = true;
          return null;
        }
        if (candidateStart.compareTo(limit) > 0) {
          return null;
        }
        if (bufferPos - lastTimeoutCheckPos >= TIMEOUT_CHECK_BYTES) {
          lastTimeoutCheckPos = bufferPos;
          if (scan.hasTimedOut()) {
            Address scanned = advanceExact(bufferBase, bufferPos - 1L);
            String canonical = AddressUtil.canonicalAddress(scanned);
            scan.visit(canonical, canonical, null);
            return null;
          }
        }
        if (needsRefill()) {
          break;
        }

        CandidateMatch utf16 =
            CandidateStringDecoders.tryDecodeUtf16(
                buffer, bufferPos, bufferLen, minCandidateLength, bigEndian);
        if (utf16 != null) {
          bufferPos += utf16.byteLength();
          lastTimeoutCheckPos = bufferPos;
          return toStreamItem(candidateStart, utf16);
        }

        CandidateMatch textMatch =
            CandidateStringDecoders.tryDecodeAsciiOrUtf8(
                buffer, bufferPos, bufferLen, minCandidateLength);
        if (textMatch != null) {
          bufferPos += textMatch.byteLength();
          lastTimeoutCheckPos = bufferPos;
          return toStreamItem(candidateStart, textMatch);
        }

        bufferPos += CandidateStringDecoders.skipNonMatchingAsciiRun(buffer, bufferPos, bufferLen);
      }
      if (bufferPos < bufferLen) {
        gapCursor = advanceExact(bufferBase, bufferPos);
        bufferLen = 0;
        bufferPos = 0;
        lastTimeoutCheckPos = 0;
      }
    }
    return null;
  }

  private boolean needsRefill() {
    if (bufferPos == 0 || bufferLen - bufferPos >= REFILL_WATERMARK_BYTES) {
      return false;
    }
    Address loadedEnd = advanceExact(bufferBase, bufferLen - 1L);
    return loadedEnd.compareTo(activeGapEnd) < 0;
  }

  private boolean fillBuffer(Address limit) {
    while (bufferPos >= bufferLen) {
      if (bufferLen > 0) {
        Address afterBuffer = advanceWithinSpace(bufferBase, bufferLen);
        if (afterBuffer != null && afterBuffer.compareTo(activeGapEnd) <= 0) {
          gapCursor = afterBuffer;
        } else {
          Address afterGap = activeGapEnd.next();
          gapCursor =
              afterGap != null
                      && afterGap.getAddressSpace().equals(activeGapEnd.getAddressSpace())
                      && afterGap.compareTo(currentRangeMax) <= 0
                  ? afterGap
                  : null;
          activeGapEnd = null;
        }
        bufferLen = 0;
        bufferPos = 0;
        lastTimeoutCheckPos = 0;
      }
      if (activeGapEnd == null && !selectNextUndefinedGap()) {
        exhausted = true;
        return false;
      }
      if (gapCursor.compareTo(limit) > 0) {
        return false;
      }
      if (scan.hasTimedOut()) {
        scan.stopOnTimeout(
            AddressUtil.canonicalAddress(gapCursor),
            ListingStringQueries.fallbackBefore(gapCursor, rangeStart, initialCursor));
        return false;
      }
      long bytesLeftMinusOne = activeGapEnd.getOffset() - gapCursor.getOffset();
      int toRead =
          Long.compareUnsigned(bytesLeftMinusOne, READ_BUFFER_BYTES - 1L) >= 0
              ? READ_BUFFER_BYTES
              : (int) bytesLeftMinusOne + 1;
      readInitializedBytes(memory, gapCursor, buffer, toRead);
      bufferBase = gapCursor;
      bufferLen = toRead;
      bufferPos = 0;
      lastTimeoutCheckPos = 0;
    }
    return true;
  }

  private boolean selectNextUndefinedGap() {
    while (true) {
      if (gapCursor == null) {
        if (!initRanges.hasNext()) {
          return false;
        }
        AddressRange nextRange = initRanges.next();
        gapCursor = nextRange.getMinAddress();
        currentRangeMax = nextRange.getMaxAddress();
      }
      if (gapCursor.compareTo(iterEnd) > 0) {
        return false;
      }

      CodeUnit defined = definedUnitAt(gapCursor);
      if (defined != null) {
        Address after = defined.getMaxAddress().next();
        if (after == null
            || !after.getAddressSpace().equals(gapCursor.getAddressSpace())
            || after.compareTo(currentRangeMax) > 0) {
          gapCursor = null;
        } else {
          gapCursor = after;
        }
        continue;
      }

      Address gapEnd = currentRangeMax;
      Instruction nextInstruction = listing.getInstructionAfter(gapCursor);
      if (nextInstruction != null
          && nextInstruction.getMinAddress().getAddressSpace().equals(gapCursor.getAddressSpace())
          && nextInstruction.getMinAddress().compareTo(gapEnd) <= 0) {
        gapEnd = nextInstruction.getMinAddress().previous();
      }
      Data nextDefinedData = listing.getDefinedDataAfter(gapCursor);
      while (nextDefinedData != null
          && nextDefinedData.getMinAddress().getAddressSpace().equals(gapCursor.getAddressSpace())
          && nextDefinedData.getMinAddress().compareTo(gapEnd) <= 0
          && isUndefinedPlaceholder(nextDefinedData)) {
        nextDefinedData = listing.getDefinedDataAfter(nextDefinedData.getMaxAddress());
      }
      if (nextDefinedData != null
          && nextDefinedData.getMinAddress().getAddressSpace().equals(gapCursor.getAddressSpace())
          && nextDefinedData.getMinAddress().compareTo(gapEnd) <= 0) {
        gapEnd = nextDefinedData.getMinAddress().previous();
      }
      activeGapEnd = gapEnd;
      return true;
    }
  }

  private CodeUnit definedUnitAt(Address address) {
    Instruction inst = listing.getInstructionContaining(address);
    if (inst != null) {
      return inst;
    }
    Data data = listing.getDefinedDataContaining(address);
    if (data != null && !isUndefinedPlaceholder(data)) {
      return data;
    }
    return null;
  }

  private static boolean isUndefinedPlaceholder(Data data) {
    return Undefined.isUndefined(data.getDataType())
        || Undefined.isUndefinedArray(data.getDataType());
  }

  private static StreamItem toStreamItem(Address start, CandidateMatch match) {
    String canonicalStart = AddressUtil.canonicalAddress(start);
    Address endAddress = advanceExact(start, match.byteLength() - 1L);
    String resumeCursor = AddressUtil.canonicalAddress(endAddress);
    String dataTypeName = match.dataTypeName();
    return new StreamItem(
        start,
        canonicalStart,
        resumeCursor,
        match.byteLength(),
        match.value(),
        match.encoding(),
        false,
        () -> DataTypeReference.named(dataTypeName));
  }

  private static void readInitializedBytes(
      Memory memory, Address start, byte[] destination, int totalLength) {
    int left = totalLength;
    int offset = 0;
    Address current = start;
    while (left > 0) {
      MemoryBlock block = memory.getBlock(current);
      if (block == null || !block.isInitialized()) {
        throw new IllegalStateException(
            "expected initialized memory block at " + AddressUtil.canonicalAddress(current));
      }
      long blockLeftMinusOne = block.getEnd().getOffset() - current.getOffset();
      int chunkSize =
          Long.compareUnsigned(blockLeftMinusOne, left - 1L) >= 0
              ? left
              : (int) blockLeftMinusOne + 1;
      int read;
      try {
        read = block.getBytes(current, destination, offset, chunkSize);
      } catch (MemoryAccessException ex) {
        throw new IllegalArgumentException(
            "unable to read initialized memory at "
                + AddressUtil.canonicalAddress(current)
                + ": "
                + ex.getMessage(),
            ex);
      }
      if (read <= 0) {
        throw new IllegalStateException(
            "empty read from initialized block at " + AddressUtil.canonicalAddress(current));
      }
      offset += read;
      left -= read;
      if (left > 0) {
        current = advanceExact(current, read);
      }
    }
  }

  private static Address advanceWithinSpace(Address address, long delta) {
    if (delta == 0) return address;
    Address max = address.getAddressSpace().getMaxAddress();
    long headroom = max.getOffset() - address.getOffset();
    if (Long.compareUnsigned(headroom, delta) < 0) {
      return null;
    }
    return advanceExact(address, delta);
  }

  private static Address advanceExact(Address address, long delta) {
    if (delta == 0) return address;
    try {
      return address.addNoWrap(delta);
    } catch (AddressOverflowException ex) {
      throw new IllegalStateException("unexpected address overflow from " + address, ex);
    }
  }
}
