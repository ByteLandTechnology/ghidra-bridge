package app.byteland.ghidra.adapter.ghidra.memory;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.scan.AddressScanRanges;
import app.byteland.ghidra.adapter.ghidra.scan.BoundedAddressScan;
import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.search.BytePatternMatchesResource;
import app.byteland.ghidra.service.search.ByteSearchResult;
import app.byteland.ghidra.service.search.SearchService.ByteSearchQuery;
import app.byteland.ghidra.service.search.WildcardBytePattern;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Scans initialized memory blocks for batch wildcard byte patterns with bounded progress.
 */
final class MemoryByteScanner {
  private static final int CHUNK_BYTES = 65_536;
  private static final int CHECKPOINT_STRIDE = 4_096;

  private final GhidraSession context;

  MemoryByteScanner(GhidraSession context) {
    this.context = Objects.requireNonNull(context, "context");
  }

  ByteSearchResult searchBytes(ByteSearchQuery query) {
    Objects.requireNonNull(query, "query");
    List<WildcardBytePattern> patterns = new ArrayList<>(query.patterns().size());
    int maxPatternBytes = 1;
    for (int i = 0; i < query.patterns().size(); i++) {
      WildcardBytePattern parsed = WildcardBytePattern.parse(i, query.patterns().get(i));
      patterns.add(parsed);
      if (parsed.byteLength() > maxPatternBytes) {
        maxPatternBytes = parsed.byteLength();
      }
    }

    int normalizedLimit = Page.clampLimit(query.limit());
    int timeoutMs =
        query.scan().timeoutMs() == null
            ? AddressScanOptions.DEFAULT_TIMEOUT_MS
            : query.scan().timeoutMs();
    AddressScanRanges.Resolved range = AddressScanRanges.resolve(context, query.scan(), true);
    AddressSpace targetSpace = range.start().getAddressSpace();

    CursorPosition resume = parseCursor(query.cursor(), patterns.size(), targetSpace);
    Address effectiveStart = range.start();
    if (resume != null && resume.address().compareTo(effectiveStart) > 0) {
      effectiveStart = resume.address();
    }

    BoundedAddressScan<RawByteMatch> scan =
        BoundedAddressScan.start(normalizedLimit, timeoutMs, range.startText(), range.endText());

    if (range.end() != null && effectiveStart.compareTo(range.end()) > 0) {
      return toResult(patterns, scan.finish());
    }

    Memory memory = context.currentProgram().getMemory();
    byte[] buffer = new byte[CHUNK_BYTES + maxPatternBytes];
    int lastPatternIdx = patterns.size() - 1;

    for (MemoryBlock block : memory.getBlocks()) {
      if (scan.stopped()) break;
      if (!block.isInitialized()) continue;
      if (!block.getStart().getAddressSpace().equals(targetSpace)) continue;
      if (block.getEnd().compareTo(effectiveStart) < 0) continue;
      if (range.end() != null && block.getStart().compareTo(range.end()) > 0) break;

      Address blockStart =
          block.getStart().compareTo(effectiveStart) > 0 ? block.getStart() : effectiveStart;
      Address blockLastStart =
          range.end() != null && range.end().compareTo(block.getEnd()) < 0
              ? range.end()
              : block.getEnd();
      scanInitializedBlock(
          memory,
          block,
          blockStart,
          blockLastStart,
          patterns,
          maxPatternBytes,
          lastPatternIdx,
          resume,
          buffer,
          scan);
    }

    return toResult(patterns, scan.finish());
  }

  private void scanInitializedBlock(
      Memory memory,
      MemoryBlock block,
      Address blockStart,
      Address blockLastStart,
      List<WildcardBytePattern> patterns,
      int maxPatternBytes,
      int lastPatternIdx,
      CursorPosition resume,
      byte[] buffer,
      BoundedAddressScan<RawByteMatch> scan) {
    Address chunkAddr = blockStart;
    scan.anchorStart(AddressUtil.canonicalAddress(blockStart));

    while (!scan.stopped() && chunkAddr != null && chunkAddr.compareTo(blockLastStart) <= 0) {
      long startsInChunkLong = safeDistanceInclusive(chunkAddr, blockLastStart);
      int startsInChunk = (int) Math.min(CHUNK_BYTES, startsInChunkLong);
      long availableBytesLong = safeDistanceInclusive(chunkAddr, block.getEnd());
      int bytesToRead =
          (int) Math.min(buffer.length, Math.min(availableBytesLong, (long) startsInChunk + maxPatternBytes - 1L));

      int readCount;
      try {
        readCount = memory.getBytes(chunkAddr, buffer, 0, bytesToRead);
      } catch (MemoryAccessException error) {
        throw new IllegalStateException(
            "unable to read initialized block " + block.getName() + ": " + error.getMessage(),
            error);
      }
      if (readCount <= 0) break;

      int scanCount = Math.min(startsInChunk, readCount);
      int sinceCheckpoint = 0;
      for (int offset = 0; offset < scanCount && !scan.stopped(); offset++) {
        Address currentAddr = addOffset(chunkAddr, offset);
        int firstPattern = 0;
        if (resume != null && currentAddr.equals(resume.address())) {
          firstPattern = resume.patternIndex() + 1;
        }
        boolean matchedAtOffset = false;
        String canonical = null;
        for (int p = firstPattern; p < patterns.size(); p++) {
          WildcardBytePattern pattern = patterns.get(p);
          if (pattern.matches(buffer, offset, readCount)) {
            if (canonical == null) {
              canonical = AddressUtil.canonicalAddress(currentAddr);
            }
            matchedAtOffset = true;
            sinceCheckpoint = 0;
            scan.visit(canonical, canonical + "@" + p, new RawByteMatch(p, canonical));
            if (scan.stopped()) break;
          }
        }
        if (!matchedAtOffset) {
          sinceCheckpoint++;
          if (sinceCheckpoint >= CHECKPOINT_STRIDE) {
            sinceCheckpoint = 0;
            String checkpointAddr = AddressUtil.canonicalAddress(currentAddr);
            scan.visit(checkpointAddr, checkpointAddr + "@" + lastPatternIdx, null);
          }
        }
      }

      if (!scan.stopped()) {
        Address chunkLastVisited = addOffset(chunkAddr, scanCount - 1);
        String completedAddr = AddressUtil.canonicalAddress(chunkLastVisited);
        scan.visit(completedAddr, completedAddr + "@" + lastPatternIdx, null);
      }

      if (scanCount >= startsInChunkLong) {
        break;
      }
      chunkAddr = advanceAddressOrNull(chunkAddr, scanCount, blockLastStart);
    }
  }

  private CursorPosition parseCursor(String rawCursor, int patternCount, AddressSpace targetSpace) {
    if (rawCursor == null || rawCursor.isBlank()) {
      return null;
    }
    int sep = rawCursor.lastIndexOf('@');
    if (sep <= 0 || sep == rawCursor.length() - 1) {
      throw new IllegalArgumentException("invalid byte search cursor");
    }
    Address addr = context.parseAddress(rawCursor.substring(0, sep));
    if (!addr.getAddressSpace().equals(targetSpace)) {
      throw new IllegalArgumentException("cursor address space does not match scan range");
    }
    int patternIdx;
    try {
      patternIdx = Integer.parseInt(rawCursor.substring(sep + 1));
    } catch (NumberFormatException error) {
      throw new IllegalArgumentException("invalid byte search cursor pattern index", error);
    }
    if (patternIdx < 0 || patternIdx >= patternCount) {
      throw new IllegalArgumentException("cursor pattern index out of bounds");
    }
    return new CursorPosition(addr, patternIdx);
  }

  private static ByteSearchResult toResult(
      List<WildcardBytePattern> patterns, Page<RawByteMatch> page) {
    List<List<String>> buckets = new ArrayList<>(patterns.size());
    for (int i = 0; i < patterns.size(); i++) {
      buckets.add(new ArrayList<>());
    }
    for (RawByteMatch hit : page.items()) {
      buckets.get(hit.patternIndex()).add(hit.address());
    }
    List<BytePatternMatchesResource> grouped = new ArrayList<>(patterns.size());
    for (int i = 0; i < patterns.size(); i++) {
      List<String> matches = buckets.get(i);
      grouped.add(
          new BytePatternMatchesResource(
              i, patterns.get(i).rawPattern(), matches, matches.size()));
    }
    return new ByteSearchResult(grouped, page.items().size(), page.nextCursor(), page.scanProgress());
  }

  private static long safeDistanceInclusive(Address start, Address end) {
    long diff = end.subtract(start);
    if (diff < 0 || diff == Long.MAX_VALUE) {
      return CHUNK_BYTES;
    }
    return diff + 1L;
  }

  private static Address addOffset(Address base, int offset) {
    if (offset == 0) return base;
    try {
      return base.addNoWrap(offset);
    } catch (AddressOverflowException overflow) {
      throw new IllegalStateException("address overflow inside block", overflow);
    }
  }

  private static Address advanceAddressOrNull(Address base, int step, Address maxInclusive) {
    try {
      Address next = base.addNoWrap(step);
      return next.compareTo(maxInclusive) <= 0 ? next : null;
    } catch (AddressOverflowException overflow) {
      return null;
    }
  }

  private record CursorPosition(Address address, int patternIndex) {}

  private record RawByteMatch(int patternIndex, String address) {}
}
