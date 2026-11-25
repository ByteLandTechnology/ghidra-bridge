package app.byteland.ghidra.adapter.ghidra.search;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraDataTypeReferences;
import app.byteland.ghidra.service.search.StringMatchResource;
import app.byteland.ghidra.service.search.StringMatchResource.Encoding;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.util.DefinedStringIterator;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Extracts decoded ASCII and UTF-16 strings from defined items and undefined initialized bytes.
 */
final class StringScanner {
  static final int DEFAULT_UNDEFINED_MIN_CHARS = 4;
  private static final int CHUNK_BYTES = 65_536;
  private static final int DEADLINE_CHECK_MASK = 0xFFF;

  private StringScanner() {}

  record ScanOutcome(List<StringMatchResource> entries, boolean timedOut, boolean capped) {}

  static ScanOutcome scan(
      Program program,
      AddressSetView targetAddresses,
      int maxEntries,
      int maxStringBytes,
      long deadlineNanos) {
    Memory memory = program.getMemory();
    AddressSet initializedTarget =
        memory.getAllInitializedAddressSet().intersect(targetAddresses);
    if (initializedTarget.isEmpty() || maxEntries <= 0) {
      return new ScanOutcome(List.of(), false, false);
    }

    Map<String, StringMatchResource> byAddress = new LinkedHashMap<>();
    boolean programBigEndian = program.getLanguage().isBigEndian();

    DefinedStringIterator definedStrings =
        DefinedStringIterator.forProgram(program, initializedTarget);
    int definedVisited = 0;
    while (definedStrings.hasNext()) {
      if ((definedVisited++ & 0xFF) == 0 && System.nanoTime() >= deadlineNanos) {
        return finish(byAddress, true, false);
      }
      Data data = definedStrings.next();
      if (data == null || data.getLength() <= 0) continue;
      int boundedBytes = Math.min(data.getLength(), maxStringBytes);
      StringDataInstance instance =
          data.getLength() <= maxStringBytes
              ? StringDataInstance.getStringDataInstance(data)
              : StringDataInstance.getStringDataInstance(
                  data.getDataType(), data, data, boundedBytes);
      if (instance == null || instance == StringDataInstance.NULL_INSTANCE) continue;
      String value = instance.getStringValue();
      if (value == null || value.isEmpty()) continue;

      String canonical = AddressUtil.canonicalAddress(data.getAddress());
      Encoding encoding = classifyCharset(instance.getCharsetName(), programBigEndian);
      byAddress.put(
          canonical,
          new StringMatchResource(
              canonical,
              value,
              boundedBytes,
              encoding,
              true,
              GhidraDataTypeReferences.toReference(data.getDataType())));
      if (byAddress.size() >= maxEntries) {
        return finish(byAddress, false, true);
      }
    }

    TaskMonitor deadlineMonitor =
        new TaskMonitorAdapter() {
          @Override
          public boolean isCancelled() {
            return System.nanoTime() >= deadlineNanos;
          }

          @Override
          public void checkCancelled() throws CancelledException {
            if (isCancelled()) {
              throw new CancelledException();
            }
          }
        };
    AddressSetView undefinedSet;
    try {
      undefinedSet =
          program.getListing().getUndefinedRanges(initializedTarget, true, deadlineMonitor);
    } catch (CancelledException cancelled) {
      return finish(byAddress, true, false);
    }
    if (!undefinedSet.isEmpty()) {
      int bufferCapacity = Math.max(CHUNK_BYTES, maxStringBytes * 2 + 16);
      byte[] buffer = new byte[bufferCapacity];
      AddressRangeIterator ranges = undefinedSet.getAddressRanges(true);
      while (ranges.hasNext()) {
        if (System.nanoTime() >= deadlineNanos) {
          return finish(byAddress, true, false);
        }
        AddressRange range = ranges.next();
        ScanStatus status =
            scanUndefinedRange(
                memory,
                range,
                programBigEndian,
                maxEntries,
                maxStringBytes,
                deadlineNanos,
                buffer,
                byAddress);
        if (status == ScanStatus.TIMED_OUT) {
          return finish(byAddress, true, false);
        }
        if (status == ScanStatus.CAPPED) {
          return finish(byAddress, false, true);
        }
      }
    }

    return finish(byAddress, false, false);
  }

  private enum ScanStatus {
    COMPLETED,
    TIMED_OUT,
    CAPPED
  }

  private static ScanStatus scanUndefinedRange(
      Memory memory,
      AddressRange range,
      boolean programBigEndian,
      int maxEntries,
      int maxStringBytes,
      long deadlineNanos,
      byte[] buffer,
      Map<String, StringMatchResource> out) {
    Address windowBase = range.getMinAddress();
    Address rangeMax = range.getMaxAddress();
    int buffered = fillBuffer(memory, windowBase, rangeMax, buffer, 0);
    if (buffered < DEFAULT_UNDEFINED_MIN_CHARS) {
      return ScanStatus.COMPLETED;
    }

    int index = 0;
    int refillThreshold = buffer.length - (maxStringBytes + 8);

    while (index < buffered) {
      if ((index & DEADLINE_CHECK_MASK) == 0 && System.nanoTime() >= deadlineNanos) {
        return ScanStatus.TIMED_OUT;
      }

      if (index >= refillThreshold) {
        Address nextUnread = addOffsetOrNull(windowBase, buffered, rangeMax);
        if (nextUnread != null) {
          int unread = buffered - index;
          System.arraycopy(buffer, index, buffer, 0, unread);
          windowBase = addOffset(windowBase, index);
          buffered = unread + fillBuffer(memory, nextUnread, rangeMax, buffer, unread);
          index = 0;
          if (buffered < DEFAULT_UNDEFINED_MIN_CHARS) {
            break;
          }
        }
      }

      int asciiBytes = measureAsciiRun(buffer, index, buffered, maxStringBytes);
      if (asciiBytes >= DEFAULT_UNDEFINED_MIN_CHARS) {
        Address matchAddr = addOffset(windowBase, index);
        String canonical = AddressUtil.canonicalAddress(matchAddr);
        String text = new String(buffer, index, asciiBytes, StandardCharsets.US_ASCII);
        out.putIfAbsent(
            canonical,
            new StringMatchResource(canonical, text, asciiBytes, Encoding.ASCII, false, null));
        if (out.size() >= maxEntries) {
          return ScanStatus.CAPPED;
        }
        index += asciiBytes;
        if (index < buffered && buffer[index] == 0) {
          index++;
        }
        continue;
      }

      int leChars = measureUtf16Run(buffer, index, buffered, maxStringBytes, true);
      int beChars = measureUtf16Run(buffer, index, buffered, maxStringBytes, false);

      if (beChars >= DEFAULT_UNDEFINED_MIN_CHARS) {
        int nextLeChars = measureUtf16Run(buffer, index + 1, buffered, maxStringBytes, true);
        if (shouldDeferBeToNextLe(windowBase, index, beChars, nextLeChars, programBigEndian)) {
          index++;
          continue;
        }
      }

      if (leChars >= DEFAULT_UNDEFINED_MIN_CHARS && leChars >= beChars) {
        int nextBeChars = measureUtf16Run(buffer, index + 1, buffered, maxStringBytes, false);
        if (shouldDeferLeToNextBe(windowBase, index, leChars, nextBeChars, programBigEndian)) {
          index++;
          continue;
        }
        int byteLen = leChars * 2;
        Address matchAddr = addOffset(windowBase, index);
        String canonical = AddressUtil.canonicalAddress(matchAddr);
        String text = new String(buffer, index, byteLen, StandardCharsets.UTF_16LE);
        out.putIfAbsent(
            canonical,
            new StringMatchResource(canonical, text, byteLen, Encoding.UTF16LE, false, null));
        if (out.size() >= maxEntries) {
          return ScanStatus.CAPPED;
        }
        index += byteLen;
        if (index + 1 < buffered && buffer[index] == 0 && buffer[index + 1] == 0) {
          index += 2;
        }
        continue;
      }

      if (beChars >= DEFAULT_UNDEFINED_MIN_CHARS) {
        int byteLen = beChars * 2;
        Address matchAddr = addOffset(windowBase, index);
        String canonical = AddressUtil.canonicalAddress(matchAddr);
        String text = new String(buffer, index, byteLen, StandardCharsets.UTF_16BE);
        out.putIfAbsent(
            canonical,
            new StringMatchResource(canonical, text, byteLen, Encoding.UTF16BE, false, null));
        if (out.size() >= maxEntries) {
          return ScanStatus.CAPPED;
        }
        index += byteLen;
        if (index + 1 < buffered && buffer[index] == 0 && buffer[index + 1] == 0) {
          index += 2;
        }
        continue;
      }

      index++;
    }

    return ScanStatus.COMPLETED;
  }

  private static boolean shouldDeferBeToNextLe(
      Address windowBase, int index, int beChars, int nextLeChars, boolean programBigEndian) {
    if (nextLeChars < DEFAULT_UNDEFINED_MIN_CHARS) return false;
    if (nextLeChars > beChars) return true;
    if (nextLeChars < beChars) return false;
    boolean currentAligned = ((windowBase.getOffset() + index) & 1L) == 0L;
    if (!currentAligned) return true;
    return false;
  }

  private static boolean shouldDeferLeToNextBe(
      Address windowBase, int index, int leChars, int nextBeChars, boolean programBigEndian) {
    if (nextBeChars < DEFAULT_UNDEFINED_MIN_CHARS) return false;
    if (nextBeChars > leChars) return true;
    if (nextBeChars < leChars) return false;
    boolean currentAligned = ((windowBase.getOffset() + index) & 1L) == 0L;
    if (!currentAligned && programBigEndian) return true;
    return false;
  }

  private static int measureAsciiRun(
      byte[] buffer, int start, int buffered, int maxStringBytes) {
    int limit = Math.min(buffered, start + maxStringBytes);
    int count = 0;
    boolean hasVisible = false;
    for (int i = start; i < limit; i++) {
      int b = buffer[i] & 0xFF;
      if (!isPrintableAsciiByte(b)) break;
      if (isVisibleAsciiByte(b)) hasVisible = true;
      count++;
    }
    return hasVisible ? count : 0;
  }

  private static int measureUtf16Run(
      byte[] buffer, int start, int buffered, int maxStringBytes, boolean littleEndian) {
    int maxChars = Math.max(1, maxStringBytes / 2);
    int limit = Math.min(buffered - 1, start + maxChars * 2 - 1);
    int chars = 0;
    boolean hasVisible = false;
    for (int i = start; i <= limit; i += 2) {
      int lowByte = buffer[littleEndian ? i : i + 1] & 0xFF;
      int highByte = buffer[littleEndian ? i + 1 : i] & 0xFF;
      if (highByte != 0 || !isPrintableAsciiByte(lowByte)) break;
      if (isVisibleAsciiByte(lowByte)) hasVisible = true;
      chars++;
    }
    return hasVisible ? chars : 0;
  }

  static boolean isPrintableAsciiByte(int value) {
    return (value >= 0x20 && value <= 0x7E) || value == 0x09 || value == 0x0A || value == 0x0D;
  }

  private static boolean isVisibleAsciiByte(int value) {
    return value >= 0x21 && value <= 0x7E;
  }

  private static Encoding classifyCharset(String charsetName, boolean programBigEndian) {
    if (charsetName == null || charsetName.isBlank()) {
      return Encoding.ASCII;
    }
    String upper = charsetName.toUpperCase(Locale.ROOT);
    if (upper.contains("UTF-16BE") || upper.contains("UTF16BE")) {
      return Encoding.UTF16BE;
    }
    if (upper.contains("UTF-16LE") || upper.contains("UTF16LE")) {
      return Encoding.UTF16LE;
    }
    if (upper.contains("UTF-16") || upper.contains("UTF16") || upper.contains("UNICODE")) {
      return programBigEndian ? Encoding.UTF16BE : Encoding.UTF16LE;
    }
    return Encoding.ASCII;
  }

  private static ScanOutcome finish(
      Map<String, StringMatchResource> byAddress, boolean timedOut, boolean capped) {
    List<StringMatchResource> sorted = new ArrayList<>(byAddress.values());
    sorted.sort(Comparator.comparing(StringMatchResource::address));
    return new ScanOutcome(List.copyOf(sorted), timedOut, capped);
  }

  private static int fillBuffer(
      Memory memory, Address start, Address maxInclusive, byte[] buffer, int destOffset) {
    int capacity = buffer.length - destOffset;
    if (capacity <= 0) return 0;
    long remaining = maxInclusive.subtract(start);
    int toRead =
        remaining < 0 || remaining >= capacity ? capacity : (int) (remaining + 1L);
    try {
      return Math.max(0, memory.getBytes(start, buffer, destOffset, toRead));
    } catch (MemoryAccessException error) {
      return 0;
    }
  }

  private static Address addOffset(Address base, int offset) {
    if (offset == 0) return base;
    try {
      return base.addNoWrap(offset);
    } catch (AddressOverflowException overflow) {
      throw new IllegalStateException("address overflow inside undefined range", overflow);
    }
  }

  private static Address addOffsetOrNull(Address base, int offset, Address maxInclusive) {
    try {
      Address next = base.addNoWrap(offset);
      return next.compareTo(maxInclusive) <= 0 ? next : null;
    } catch (AddressOverflowException overflow) {
      return null;
    }
  }
}
