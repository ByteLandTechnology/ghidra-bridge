package app.byteland.ghidra.adapter.ghidra.memory;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.scan.AddressScanRanges;
import app.byteland.ghidra.adapter.ghidra.scan.BoundedAddressScan;
import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.memory.MemoryMatchResource;
import app.byteland.ghidra.service.memory.MemoryService.MemoryFindQuery;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import java.util.HexFormat;

/**
 * Searches initialized memory ranges for wildcard byte patterns with bounded scan budgets.
 */
final class MemorySearchQueries {
  private static final int STEP_STARTS = 4096;

  private final GhidraSession context;

  MemorySearchQueries(GhidraSession context) {
    this.context = context;
  }

  Page<MemoryMatchResource> findMemory(MemoryFindQuery query) {
    WildcardBytePattern pattern = WildcardBytePattern.parse(query.pattern());
    int normalizedLimit = Page.clampLimit(query.limit());
    AddressScanRanges.Resolved range = AddressScanRanges.resolve(context, query.scan(), true);

    BoundedAddressScan<MemoryMatchResource> scan =
        BoundedAddressScan.start(
            normalizedLimit, query.scan().timeoutMs(), range.startText(), range.endText());

    Address effectiveStart = resolveEffectiveStart(range, query.cursor());
    if (effectiveStart == null) {
      return scan.finish();
    }

    int patternLen = pattern.length();
    Address readLimitEnd =
        range.end() == null
            ? effectiveStart.getAddressSpace().getMaxAddress()
            : advanceClamped(range.end(), patternLen - 1L);

    Memory memory = context.currentProgram().getMemory();
    AddressSetView initialized =
        memory
            .getAllInitializedAddressSet()
            .intersect(new AddressSet(effectiveStart, readLimitEnd));

    byte[] buffer = new byte[STEP_STARTS + patternLen - 1];
    HexFormat hex = HexFormat.of();
    String previousTested = null;

    AddressRangeIterator ranges = initialized.getAddressRanges();
    while (ranges.hasNext() && !scan.stopped()) {
      AddressRange initRange = ranges.next();
      Address windowStart = initRange.getMinAddress();
      Address rangeMax = initRange.getMaxAddress();

      while (windowStart != null && !range.afterEnd(windowStart) && !scan.stopped()) {
        long maxMinusStart = rangeMax.getOffset() - windowStart.getOffset();
        if (Long.compareUnsigned(maxMinusStart, patternLen - 1L) < 0) {
          break;
        }
        int maxStarts = computeWindowStarts(windowStart, rangeMax, range.end(), patternLen);
        if (maxStarts <= 0) {
          break;
        }
        if (scan.hasTimedOut()) {
          scan.stopOnTimeout(AddressUtil.canonicalAddress(windowStart), previousTested);
          break;
        }

        int bytesToRead = maxStarts + patternLen - 1;
        readInitializedBytes(memory, windowStart, buffer, bytesToRead);

        boolean visitedLastIndex = false;
        for (int index = 0; index < maxStarts; index++) {
          if (pattern.matchesAt(buffer, index)) {
            Address matchAddr = advanceExact(windowStart, index);
            String canonical = AddressUtil.canonicalAddress(matchAddr);
            String matchedHex = hex.formatHex(buffer, index, index + patternLen);
            MemoryMatchResource match =
                new MemoryMatchResource(
                    canonical,
                    patternLen,
                    new ByteSequence(ByteSequence.Encoding.HEX, matchedHex, patternLen));
            scan.visit(canonical, canonical, match);
            previousTested = canonical;
            if (index == maxStarts - 1) {
              visitedLastIndex = true;
            }
            if (scan.stopped()) {
              return scan.finish();
            }
          }
        }

        if (!visitedLastIndex) {
          Address stepEnd = advanceExact(windowStart, maxStarts - 1L);
          String canonical = AddressUtil.canonicalAddress(stepEnd);
          scan.visit(canonical, canonical, null);
          previousTested = canonical;
          if (scan.stopped()) {
            return scan.finish();
          }
        }

        long availableStartsMinusOne = maxMinusStart - (patternLen - 1L);
        if (Long.compareUnsigned(availableStartsMinusOne, maxStarts) < 0) {
          break;
        }
        windowStart = advanceExact(windowStart, maxStarts);
      }
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

  private static int computeWindowStarts(
      Address windowStart, Address rangeMax, Address scanEnd, int patternLen) {
    long maxMinusStart = rangeMax.getOffset() - windowStart.getOffset();
    long availableMinusOne = maxMinusStart - (patternLen - 1L);
    int limitByInit =
        Long.compareUnsigned(availableMinusOne, STEP_STARTS - 1L) >= 0
            ? STEP_STARTS
            : (int) availableMinusOne + 1;
    if (scanEnd == null) {
      return limitByInit;
    }
    long endMinusStart = scanEnd.getOffset() - windowStart.getOffset();
    int limitByEnd =
        Long.compareUnsigned(endMinusStart, STEP_STARTS - 1L) >= 0
            ? STEP_STARTS
            : (int) endMinusStart + 1;
    return Math.min(limitByInit, limitByEnd);
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

  private static Address advanceClamped(Address address, long delta) {
    if (delta <= 0) return address;
    Address max = address.getAddressSpace().getMaxAddress();
    long headroom = max.getOffset() - address.getOffset();
    if (Long.compareUnsigned(headroom, delta) <= 0) {
      return max;
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
