package app.byteland.ghidra.adapter.ghidra.listing;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraDataTypeReferences;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.scan.AddressScanRanges;
import app.byteland.ghidra.adapter.ghidra.scan.BoundedAddressScan;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.listing.ListingService.StringQuery;
import app.byteland.ghidra.service.listing.StringResource;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.DefinedStringIterator;
import java.nio.charset.StandardCharsets;

/**
 * Queries defined strings and optional candidate strings in undefined initialized memory.
 */
final class ListingStringQueries {
  private static final int READ_BUFFER_BYTES = 65_536;
  private static final int REFILL_WATERMARK_BYTES = 8_192;
  private static final int MAX_CANDIDATE_BYTES = 8_192;
  private static final int TIMEOUT_CHECK_BYTES = 4_096;

  private final GhidraSession context;

  ListingStringQueries(GhidraSession context) {
    this.context = context;
  }

  Page<StringResource> listStrings(StringQuery query) {
    StringFilterMatcher matcher = StringFilterMatcher.compile(query);
    int normalizedLimit = Page.clampLimit(query.limit());
    AddressScanRanges.Resolved range = AddressScanRanges.resolve(context, query.scan(), true);

    BoundedAddressScan<StringResource> scan =
        BoundedAddressScan.start(
            normalizedLimit, query.scan().timeoutMs(), range.startText(), range.endText());

    Address effectiveStart = resolveEffectiveStart(range, query.cursor());
    if (effectiveStart == null) {
      return scan.finish();
    }

    Program program = context.currentProgram();
    Address iterEnd =
        range.end() != null ? range.end() : effectiveStart.getAddressSpace().getMaxAddress();

    DefinedStream definedStream = new DefinedStream(program, effectiveStart, iterEnd);
    CandidateStream candidateStream =
        query.includeCandidates()
            ? new CandidateStream(program, effectiveStart, iterEnd, matcher.minCandidateLength(), scan)
            : null;

    String previousCursor = query.cursor() == null ? null : AddressUtil.canonicalAddress(context.parseAddress(query.cursor()));

    while (!scan.stopped()) {
      StreamItem nextDefined = definedStream.peek();
      StreamItem nextCandidate = candidateStream == null ? null : candidateStream.peek();
      if (scan.stopped()) {
        break;
      }
      if (nextDefined == null && nextCandidate == null) {
        break;
      }

      final StreamItem chosen;
      if (nextCandidate == null) {
        chosen = definedStream.take();
      } else if (nextDefined == null) {
        chosen = candidateStream.take();
      } else {
        int cmp = nextDefined.address().compareTo(nextCandidate.address());
        if (cmp <= 0) {
          chosen = definedStream.take();
          if (cmp == 0) {
            candidateStream.take();
          }
        } else {
          chosen = candidateStream.take();
        }
      }

      if (scan.hasTimedOut()) {
        scan.stopOnTimeout(chosen.canonicalAddress(), fallbackBefore(chosen.address(), range.start(), previousCursor));
        break;
      }

      boolean matched;
      try {
        matched =
            matcher.matches(chosen.resource(), scan.nanoTimeSupplier(), scan.deadlineNanos());
      } catch (StringFilterMatcher.RegexTimeoutException timeout) {
        scan.stopOnTimeout(chosen.canonicalAddress(), fallbackBefore(chosen.address(), range.start(), previousCursor));
        break;
      }

      scan.visit(chosen.canonicalAddress(), chosen.resumeCursor(), matched ? chosen.resource() : null);
      previousCursor = chosen.resumeCursor();
    }

    return scan.finish();
  }

  private Address resolveEffectiveStart(AddressScanRanges.Resolved range, String cursorRaw) {
    if (cursorRaw == null) {
      return range.start();
    }
    Address cursor = context.parseAddress(cursorRaw);
    if (!cursor.getAddressSpace().equals(range.start().getAddressSpace())) {
      throw new IllegalArgumentException("cursor must be in the scan address space");
    }
    if (range.end() != null && cursor.compareTo(range.end()) >= 0) {
      return null;
    }
    Address next = cursor.next();
    if (next == null || !next.getAddressSpace().equals(cursor.getAddressSpace())) {
      return null;
    }
    return next.compareTo(range.start()) > 0 ? next : range.start();
  }

  private static String fallbackBefore(Address current, Address rangeStart, String previousCursor) {
    if (previousCursor != null) {
      return previousCursor;
    }
    if (current.compareTo(rangeStart) > 0) {
      Address prev = current.previous();
      if (prev != null && prev.getAddressSpace().equals(current.getAddressSpace())) {
        return AddressUtil.canonicalAddress(prev);
      }
    }
    return null;
  }

  private record StreamItem(
      Address address, String canonicalAddress, String resumeCursor, StringResource resource) {}

  private static final class DefinedStream {
    private final Program program;
    private final Address effectiveStart;
    private final Address iterEnd;
    private final DefinedStringIterator iterator;
    private final boolean bigEndian;
    private StreamItem nextItem;
    private boolean exhausted;

    DefinedStream(Program program, Address effectiveStart, Address iterEnd) {
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
        StringResource resource =
            new StringResource(
                canonical,
                data.getLength(),
                value,
                encoding,
                true,
                GhidraDataTypeReferences.toReference(data.getDataType()));
        return new StreamItem(address, canonical, canonical, resource);
      }
      return null;
    }

    private static String normalizeDefinedCharset(String rawCharset, boolean bigEndian) {
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

  private static final class CandidateStream {
    private final Program program;
    private final Listing listing;
    private final Memory memory;
    private final Address iterEnd;
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

    CandidateStream(
        Program program,
        Address effectiveStart,
        Address iterEnd,
        int minCandidateLength,
        BoundedAddressScan<StringResource> scan) {
      this.program = program;
      this.listing = program.getListing();
      this.memory = program.getMemory();
      this.iterEnd = iterEnd;
      this.minCandidateLength = minCandidateLength;
      this.bigEndian = program.getLanguage().isBigEndian();
      this.scan = scan;
      AddressSetView initialized =
          memory.getAllInitializedAddressSet().intersect(new AddressSet(effectiveStart, iterEnd));
      this.initRanges = initialized.getAddressRanges();
    }

    StreamItem peek() {
      if (nextItem == null && !exhausted && !scan.stopped()) {
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
      while (!scan.stopped()) {
        if (!ensureBufferReady()) {
          return null;
        }
        while (bufferPos < bufferLen) {
          if (bufferPos - lastTimeoutCheckPos >= TIMEOUT_CHECK_BYTES) {
            lastTimeoutCheckPos = bufferPos;
            if (scan.hasTimedOut()) {
              Address scanned = advanceExact(bufferBase, bufferPos - 1L);
              String canonical = AddressUtil.canonicalAddress(scanned);
              scan.stopOnTimeout(canonical, canonical);
              return null;
            }
          }
          if (needsRefill()) {
            break;
          }

          Address candidateStart = advanceExact(bufferBase, bufferPos);
          if (candidateStart.compareTo(iterEnd) > 0) {
            return null;
          }

          CandidateMatch utf16 = tryDecodeUtf16(buffer, bufferPos, bufferLen, minCandidateLength, bigEndian);
          if (utf16 != null) {
            bufferPos += utf16.byteLength();
            lastTimeoutCheckPos = bufferPos;
            return toStreamItem(candidateStart, utf16);
          }

          CandidateMatch textMatch = tryDecodeAsciiOrUtf8(buffer, bufferPos, bufferLen, minCandidateLength);
          if (textMatch != null) {
            bufferPos += textMatch.byteLength();
            lastTimeoutCheckPos = bufferPos;
            return toStreamItem(candidateStart, textMatch);
          }

          bufferPos += skipNonMatchingAsciiRun(buffer, bufferPos, bufferLen);
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

    private boolean ensureBufferReady() {
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
        if (activeGapEnd == null) {
          if (!selectNextUndefinedGap()) {
            return false;
          }
        }
        if (scan.hasTimedOut()) {
          Address prev = gapCursor.previous();
          String fallback =
              prev != null && prev.getAddressSpace().equals(gapCursor.getAddressSpace())
                  ? AddressUtil.canonicalAddress(prev)
                  : null;
          scan.stopOnTimeout(AddressUtil.canonicalAddress(gapCursor), fallback);
          return false;
        }
        long remainingMinusOne = activeGapEnd.getOffset() - gapCursor.getOffset();
        int toRead =
            Long.compareUnsigned(remainingMinusOne, READ_BUFFER_BYTES - 1L) >= 0
                ? READ_BUFFER_BYTES
                : (int) remainingMinusOne + 1;
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
          if (currentRangeMax.compareTo(iterEnd) > 0) {
            // Retain extra bytes in the initialized block for null terminators.
          }
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

    private StreamItem toStreamItem(Address start, CandidateMatch match) {
      String canonicalStart = AddressUtil.canonicalAddress(start);
      Address endAddress = advanceExact(start, match.byteLength() - 1L);
      String resumeCursor = AddressUtil.canonicalAddress(endAddress);
      StringResource resource =
          new StringResource(
              canonicalStart,
              match.byteLength(),
              match.value(),
              match.encoding(),
              false,
              DataTypeReference.named(match.dataTypeName()));
      return new StreamItem(start, canonicalStart, resumeCursor, resource);
    }
  }

  private record CandidateMatch(
      String value, int byteLength, String encoding, String dataTypeName) {}

  private static CandidateMatch tryDecodeUtf16(
      byte[] buf, int start, int limit, int minCandidateLen, boolean programBigEndian) {
    if (start + 1 >= limit) {
      return null;
    }
    int b0 = buf[start] & 0xFF;
    int b1 = buf[start + 1] & 0xFF;
    if (isPrintableAscii(b0) && b1 == 0) {
      int minRequired = programBigEndian ? Math.max(minCandidateLen, 4) : Math.max(minCandidateLen, 2);
      return decodeUtf16AsciiRun(buf, start, limit, minRequired, false);
    }
    if (b0 == 0 && isPrintableAscii(b1)) {
      int minRequired = programBigEndian ? Math.max(minCandidateLen, 2) : Math.max(minCandidateLen, 4);
      return decodeUtf16AsciiRun(buf, start, limit, minRequired, true);
    }
    return null;
  }

  private static CandidateMatch decodeUtf16AsciiRun(
      byte[] buf, int start, int limit, int minRequired, boolean bigEndian) {
    int maxEnd = Math.min(limit, start + MAX_CANDIDATE_BYTES);
    StringBuilder chars = new StringBuilder();
    int pos = start;
    while (pos + 1 < maxEnd) {
      int high = buf[pos] & 0xFF;
      int low = buf[pos + 1] & 0xFF;
      int codeUnit = bigEndian ? ((high << 8) | low) : ((low << 8) | high);
      if (!isPrintableAscii(codeUnit)) {
        break;
      }
      chars.append((char) codeUnit);
      pos += 2;
    }
    if (chars.length() < minRequired) {
      return null;
    }
    if (pos + 1 < limit && buf[pos] == 0 && buf[pos + 1] == 0) {
      pos += 2;
    }
    return new CandidateMatch(
        chars.toString(),
        pos - start,
        bigEndian ? "UTF-16BE" : "UTF-16LE",
        "unicode");
  }

  private static CandidateMatch tryDecodeAsciiOrUtf8(
      byte[] buf, int start, int limit, int minCandidateLen) {
    int maxEnd = Math.min(limit, start + MAX_CANDIDATE_BYTES);
    int pos = start;
    int charCount = 0;
    boolean hasMultibyteUtf8 = false;

    while (pos < maxEnd) {
      int b0 = buf[pos] & 0xFF;
      if (b0 < 0x80) {
        if (!isPrintableAscii(b0)) {
          break;
        }
        // Stop before a UTF-16LE sequence of two or more printable characters.
        if (pos > start
            && pos + 3 < maxEnd
            && buf[pos + 1] == 0
            && isPrintableAscii(buf[pos + 2] & 0xFF)
            && buf[pos + 3] == 0) {
          break;
        }
        pos += 1;
        charCount += 1;
        continue;
      }
      int utf8Bytes = decodePrintableUtf8SequenceLength(buf, pos, maxEnd);
      if (utf8Bytes <= 0) {
        break;
      }
      hasMultibyteUtf8 = true;
      pos += utf8Bytes;
      charCount += 1;
    }

    if (charCount < minCandidateLen) {
      return null;
    }
    String value = new String(buf, start, pos - start, StandardCharsets.UTF_8);
    if (value.length() < minCandidateLen) {
      return null;
    }
    int byteLength = pos - start;
    if (pos < limit && buf[pos] == 0) {
      byteLength += 1;
    }
    return new CandidateMatch(
        value,
        byteLength,
        hasMultibyteUtf8 ? "UTF-8" : "US-ASCII",
        hasMultibyteUtf8 ? "utf8" : "string");
  }

  private static int skipNonMatchingAsciiRun(byte[] buf, int start, int limit) {
    if (!isPrintableAscii(buf[start] & 0xFF)) {
      return 1;
    }
    if (start + 1 < limit && buf[start + 1] == 0) {
      return 1;
    }
    int pos = start + 1;
    while (pos < limit && isPrintableAscii(buf[pos] & 0xFF)) {
      if (pos + 1 < limit && buf[pos + 1] == 0) {
        break;
      }
      pos++;
    }
    return pos - start;
  }

  private static int decodePrintableUtf8SequenceLength(byte[] buf, int pos, int limit) {
    int b0 = buf[pos] & 0xFF;
    int needed;
    int codePoint;
    int minCodePoint;
    if (b0 >= 0xC2 && b0 <= 0xDF) {
      needed = 2;
      codePoint = b0 & 0x1F;
      minCodePoint = 0x80;
    } else if (b0 >= 0xE0 && b0 <= 0xEF) {
      needed = 3;
      codePoint = b0 & 0x0F;
      minCodePoint = 0x800;
    } else if (b0 >= 0xF0 && b0 <= 0xF4) {
      needed = 4;
      codePoint = b0 & 0x07;
      minCodePoint = 0x10000;
    } else {
      return 0;
    }
    if (pos + needed > limit) {
      return 0;
    }
    for (int i = 1; i < needed; i++) {
      int cont = buf[pos + i] & 0xFF;
      if ((cont & 0xC0) != 0x80) {
        return 0;
      }
      codePoint = (codePoint << 6) | (cont & 0x3F);
    }
    if (codePoint < minCodePoint
        || codePoint > 0x10FFFF
        || (codePoint >= 0xD800 && codePoint <= 0xDFFF)) {
      return 0;
    }
    if (Character.isISOControl(codePoint)) {
      return 0;
    }
    int type = Character.getType(codePoint);
    if (type == Character.UNASSIGNED || type == Character.PRIVATE_USE || type == Character.SURROGATE) {
      return 0;
    }
    return needed;
  }

  private static boolean isPrintableAscii(int ch) {
    return (ch >= 0x20 && ch <= 0x7E) || ch == '\t' || ch == '\n' || ch == '\r';
  }

  private static void readInitializedBytes(
      Memory memory, Address start, byte[] destination, int totalLength) {
    int remaining = totalLength;
    int offset = 0;
    Address current = start;
    while (remaining > 0) {
      MemoryBlock block = memory.getBlock(current);
      if (block == null || !block.isInitialized()) {
        throw new IllegalStateException(
            "expected initialized memory block at " + AddressUtil.canonicalAddress(current));
      }
      long blockRemainingMinusOne = block.getEnd().getOffset() - current.getOffset();
      int chunkSize =
          Long.compareUnsigned(blockRemainingMinusOne, remaining - 1L) >= 0
              ? remaining
              : (int) blockRemainingMinusOne + 1;
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
      remaining -= read;
      if (remaining > 0) {
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
