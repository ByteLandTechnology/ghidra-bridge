package app.byteland.ghidra.adapter.ghidra.search;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.scan.AddressScanRanges;
import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.analysis.AnalysisResource;
import app.byteland.ghidra.service.analysis.AnalysisService;
import app.byteland.ghidra.service.search.SearchService.EncodingFilter;
import app.byteland.ghidra.service.search.SearchService.StringSearchQuery;
import app.byteland.ghidra.service.search.StringMatchResource;
import app.byteland.ghidra.service.search.StringSearchResult;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Maintains a bounded, mutation-aware string cache for an active Ghidra session.
 */
public final class StringIndexCache {
  public static final int DEFAULT_MAX_ENTRIES = 100_000;
  public static final int DEFAULT_MAX_STRING_BYTES = 4_096;
  private static final long SMALL_BLOCK_RESCAN_THRESHOLD = 262_144L;
  private static final long NANOS_PER_MILLISECOND = 1_000_000L;
  private static final Comparator<StringMatchResource> BY_ADDRESS =
      Comparator.comparing(StringMatchResource::address);

  private final GhidraSession context;
  private final AnalysisService analysisService;
  private final int maxEntries;
  private final int maxStringBytes;
  private final Object cacheLock = new Object();

  private List<StringMatchResource> cachedEntries;
  private long cachedModificationNumber = Long.MIN_VALUE;
  private boolean dirtyFull = true;
  private final AddressSet dirtyAddresses = new AddressSet();

  public StringIndexCache(GhidraSession context, AnalysisService analysisService) {
    this(context, analysisService, DEFAULT_MAX_ENTRIES, DEFAULT_MAX_STRING_BYTES);
  }

  public StringIndexCache(
      GhidraSession context,
      AnalysisService analysisService,
      int maxEntries,
      int maxStringBytes) {
    this.context = Objects.requireNonNull(context, "context");
    this.analysisService = Objects.requireNonNull(analysisService, "analysisService");
    if (maxEntries < 1) throw new IllegalArgumentException("maxEntries must be positive");
    if (maxStringBytes < 4) throw new IllegalArgumentException("maxStringBytes must be >= 4");
    this.maxEntries = maxEntries;
    this.maxStringBytes = maxStringBytes;
    this.context.addMutationListener(this::onProgramMutated);
  }

  public void invalidateAll() {
    synchronized (cacheLock) {
      dirtyFull = true;
      dirtyAddresses.clear();
      cachedEntries = null;
    }
  }

  private void onProgramMutated(AddressSetView affectedAddresses) {
    synchronized (cacheLock) {
      if (affectedAddresses == null || affectedAddresses.isEmpty()) {
        dirtyFull = true;
        dirtyAddresses.clear();
        cachedEntries = null;
        return;
      }
      if (!dirtyFull && cachedEntries != null) {
        dirtyAddresses.add(affectedAddresses);
      } else {
        dirtyFull = true;
      }
    }
  }

  public StringSearchResult search(StringSearchQuery query) {
    Objects.requireNonNull(query, "query");
    Pattern compiledRegex = compileRegex(query.regex(), query.caseSensitive());
    boolean hasExplicitRange = query.scan().start() != null || query.scan().end() != null;
    AddressScanRanges.Resolved range =
        hasExplicitRange ? AddressScanRanges.resolve(context, query.scan(), true) : null;
    long deadlineNanos = computeDeadlineNanos(query.scan().timeoutMs());

    Snapshot snapshot = obtainSnapshot(range, deadlineNanos);
    List<StringMatchResource> candidates =
        snapshot.rangeAlreadyApplied() || range == null
            ? snapshot.entries()
            : sliceByRange(snapshot.entries(), range);
    List<StringMatchResource> matched = filterCandidates(candidates, query, compiledRegex);
    Page<StringMatchResource> page =
        Page.paginate(matched, query.limit(), query.cursor(), StringMatchResource::address);
    return new StringSearchResult(
        page, snapshot.complete(), snapshot.totalIndexed(), snapshot.modificationNumber());
  }

  private Snapshot obtainSnapshot(AddressScanRanges.Resolved range, long deadlineNanos) {
    synchronized (cacheLock) {
      Program program = context.currentProgram();
      Memory memory = program.getMemory();
      AddressSetView indexableSet = indexableAddressSet(memory);
      long modNumber = program.getModificationNumber();

      if (isAnalysisRunning()) {
        dirtyFull = true;
        dirtyAddresses.clear();
        cachedEntries = null;
        AddressSetView targetSet = range != null ? toAddressSet(program, range) : indexableSet;
        StringScanner.ScanOutcome partial =
            StringScanner.scan(program, targetSet, maxEntries, maxStringBytes, deadlineNanos);
        return new Snapshot(partial.entries(), false, partial.entries().size(), modNumber, true);
      }

      if (cachedEntries == null
          || dirtyFull
          || (dirtyAddresses.isEmpty() && cachedModificationNumber != modNumber)) {
        StringScanner.ScanOutcome full =
            StringScanner.scan(program, indexableSet, maxEntries, maxStringBytes, deadlineNanos);
        if (full.timedOut()) {
          return new Snapshot(full.entries(), false, full.entries().size(), modNumber, range == null);
        }
        cachedEntries = full.entries();
        cachedModificationNumber = program.getModificationNumber();
        dirtyFull = false;
        dirtyAddresses.clear();
      } else if (!dirtyAddresses.isEmpty()) {
        AddressSet rescanWindows = computeRescanWindows(program, dirtyAddresses);
        if (!rescanWindows.isEmpty()) {
          StringScanner.ScanOutcome updated =
              StringScanner.scan(program, rescanWindows, maxEntries, maxStringBytes, deadlineNanos);
          if (updated.timedOut()) {
            dirtyFull = true;
            dirtyAddresses.clear();
            cachedEntries = null;
            return new Snapshot(
                updated.entries(), false, updated.entries().size(), modNumber, range == null);
          }
          cachedEntries = mergeRescannedEntries(rescanWindows, cachedEntries, updated.entries());
        }
        cachedModificationNumber = program.getModificationNumber();
        dirtyAddresses.clear();
      }

      if (range != null) {
        AddressSet targetSet = toAddressSet(program, range);
        AddressSet unindexedTarget =
            memory.getAllInitializedAddressSet().intersect(targetSet).subtract(indexableSet);
        if (!unindexedTarget.isEmpty()) {
          StringScanner.ScanOutcome onDemand =
              StringScanner.scan(program, targetSet, maxEntries, maxStringBytes, deadlineNanos);
          return new Snapshot(
              onDemand.entries(),
              !onDemand.timedOut(),
              cachedEntries.size(),
              cachedModificationNumber,
              true);
        }
      }

      return new Snapshot(
          cachedEntries, true, cachedEntries.size(), cachedModificationNumber, range == null);
    }
  }

  private static AddressSetView indexableAddressSet(Memory memory) {
    AddressSetView loaded = memory.getLoadedAndInitializedAddressSet();
    return loaded.isEmpty() ? memory.getAllInitializedAddressSet() : loaded;
  }

  private AddressSet computeRescanWindows(Program program, AddressSet dirty) {
    Memory memory = program.getMemory();
    boolean loadedOnly = !memory.getLoadedAndInitializedAddressSet().isEmpty();
    Listing listing = program.getListing();
    AddressSet windows = new AddressSet();
    AddressRangeIterator iter = dirty.getAddressRanges(true);
    while (iter.hasNext()) {
      AddressRange dirtyRange = iter.next();
      for (MemoryBlock block : memory.getBlocks()) {
        if (!block.isInitialized() || (loadedOnly && !block.isLoaded())) continue;
        if (!block.getStart().getAddressSpace().equals(dirtyRange.getAddressSpace())) continue;
        if (block.getEnd().compareTo(dirtyRange.getMinAddress()) < 0) continue;
        if (block.getStart().compareTo(dirtyRange.getMaxAddress()) > 0) continue;

        if (block.getSize() <= SMALL_BLOCK_RESCAN_THRESHOLD) {
          windows.add(block.getStart(), block.getEnd());
          continue;
        }

        Address clampedMin =
            dirtyRange.getMinAddress().compareTo(block.getStart()) > 0
                ? dirtyRange.getMinAddress()
                : block.getStart();
        Address clampedMax =
            dirtyRange.getMaxAddress().compareTo(block.getEnd()) < 0
                ? dirtyRange.getMaxAddress()
                : block.getEnd();
        Address winStart = stepBackwardInBlock(block, clampedMin, maxStringBytes + 16L);
        Address winEnd = stepForwardInBlock(block, clampedMax, maxStringBytes + 16L);
        winStart = alignWindowStart(memory, listing, block, winStart);
        winEnd = alignWindowEnd(memory, listing, block, winEnd);
        windows.add(winStart, winEnd);
      }
    }
    return windows;
  }

  private Address alignWindowStart(
      Memory memory, Listing listing, MemoryBlock block, Address candidate) {
    Address current = candidate;
    Data containing = listing.getDefinedDataContaining(current);
    if (isDefinedNonUndefined(containing) && containing.getMinAddress().compareTo(current) < 0) {
      current =
          containing.getMinAddress().compareTo(block.getStart()) > 0
              ? containing.getMinAddress()
              : block.getStart();
    }
    byte[] pair = new byte[2];
    int steps = 0;
    while (current.compareTo(block.getStart()) > 0 && steps < maxStringBytes * 2) {
      try {
        if (memory.getBytes(current, pair, 0, 2) == 2
            && !StringScanner.isPrintableAsciiByte(pair[0] & 0xFF)
            && !StringScanner.isPrintableAsciiByte(pair[1] & 0xFF)
            && pair[0] == 0
            && pair[1] == 0
            && !isDefinedNonUndefined(listing.getDefinedDataContaining(current))) {
          return current;
        }
      } catch (MemoryAccessException ignored) {
        return block.getStart();
      }
      Address prev = current.previous();
      if (prev == null || prev.compareTo(block.getStart()) < 0) {
        return block.getStart();
      }
      current = prev;
      steps++;
    }
    return block.getStart();
  }

  private Address alignWindowEnd(
      Memory memory, Listing listing, MemoryBlock block, Address candidate) {
    Address current = candidate;
    Data containing = listing.getDefinedDataContaining(current);
    if (isDefinedNonUndefined(containing) && containing.getMaxAddress().compareTo(current) > 0) {
      current =
          containing.getMaxAddress().compareTo(block.getEnd()) < 0
              ? containing.getMaxAddress()
              : block.getEnd();
    }
    byte[] pair = new byte[2];
    int steps = 0;
    while (current.compareTo(block.getEnd()) < 0 && steps < maxStringBytes * 2) {
      try {
        if (memory.getBytes(current, pair, 0, 2) == 2
            && pair[0] == 0
            && pair[1] == 0
            && !isDefinedNonUndefined(listing.getDefinedDataContaining(current))) {
          return current;
        }
      } catch (MemoryAccessException ignored) {
        return block.getEnd();
      }
      Address next = current.next();
      if (next == null || next.compareTo(block.getEnd()) > 0) {
        return block.getEnd();
      }
      current = next;
      steps++;
    }
    return block.getEnd();
  }

  private static boolean isDefinedNonUndefined(Data data) {
    return data != null && !Undefined.isUndefined(data.getDataType());
  }

  private List<StringMatchResource> mergeRescannedEntries(
      AddressSet rescanWindows,
      List<StringMatchResource> existing,
      List<StringMatchResource> rescanned) {
    List<RangeKey> windowKeys = new ArrayList<>();
    AddressRangeIterator iter = rescanWindows.getAddressRanges(true);
    while (iter.hasNext()) {
      AddressRange range = iter.next();
      windowKeys.add(
          new RangeKey(
              AddressUtil.canonicalAddress(range.getMinAddress()),
              AddressUtil.canonicalAddress(range.getMaxAddress())));
    }

    List<StringMatchResource> merged = new ArrayList<>(existing.size() + rescanned.size());
    for (StringMatchResource item : existing) {
      if (!inAnyWindow(item.address(), windowKeys)) {
        merged.add(item);
      }
    }
    merged.addAll(rescanned);
    merged.sort(BY_ADDRESS);
    if (merged.size() > maxEntries) {
      return List.copyOf(merged.subList(0, maxEntries));
    }
    return List.copyOf(merged);
  }

  private static boolean inAnyWindow(String canonicalAddress, List<RangeKey> windows) {
    for (RangeKey window : windows) {
      if (compareCanonicalAddress(canonicalAddress, window.min()) >= 0
          && compareCanonicalAddress(canonicalAddress, window.max()) <= 0) {
        return true;
      }
    }
    return false;
  }

  private static List<StringMatchResource> sliceByRange(
      List<StringMatchResource> sortedEntries, AddressScanRanges.Resolved range) {
    if (sortedEntries.isEmpty()) return List.of();
    String startKey = range.startText();
    String spacePrefix = range.start().getAddressSpace().getName() + ":";
    String endKey = range.endText();

    if (endKey != null && startKey.length() == endKey.length()) {
      int startIdx = lowerBound(sortedEntries, startKey);
      if (startIdx >= sortedEntries.size()) return List.of();
      int endIdx = startIdx;
      while (endIdx < sortedEntries.size()) {
        String addr = sortedEntries.get(endIdx).address();
        if (!addr.startsWith(spacePrefix) || addr.length() != startKey.length()) break;
        if (addr.compareTo(endKey) > 0) break;
        endIdx++;
      }
      if (endIdx == sortedEntries.size()
          || !sortedEntries.get(endIdx).address().startsWith(spacePrefix)) {
        return sortedEntries.subList(startIdx, endIdx);
      }
    }

    List<StringMatchResource> filtered = new ArrayList<>();
    for (StringMatchResource item : sortedEntries) {
      String addr = item.address();
      if (!addr.startsWith(spacePrefix)) continue;
      if (compareCanonicalAddress(addr, startKey) < 0) continue;
      if (endKey != null && compareCanonicalAddress(addr, endKey) > 0) continue;
      filtered.add(item);
    }
    return filtered;
  }

  private static int compareCanonicalAddress(String left, String right) {
    int leftColon = left.lastIndexOf(':');
    int rightColon = right.lastIndexOf(':');
    if (leftColon > 0 && rightColon > 0) {
      int bySpace =
          CharSequence.compare(left.subSequence(0, leftColon), right.subSequence(0, rightColon));
      if (bySpace != 0) return bySpace;
      int leftHexLen = left.length() - leftColon - 1;
      int rightHexLen = right.length() - rightColon - 1;
      if (leftHexLen != rightHexLen) return Integer.compare(leftHexLen, rightHexLen);
      return CharSequence.compare(
          left.subSequence(leftColon + 1, left.length()),
          right.subSequence(rightColon + 1, right.length()));
    }
    return left.compareTo(right);
  }

  private static int lowerBound(List<StringMatchResource> sortedEntries, String key) {
    StringMatchResource probe =
        new StringMatchResource(key, "", 0, StringMatchResource.Encoding.ASCII, false, null);
    int pos = Collections.binarySearch(sortedEntries, probe, BY_ADDRESS);
    return pos >= 0 ? pos : -(pos + 1);
  }

  private static List<StringMatchResource> filterCandidates(
      List<StringMatchResource> candidates, StringSearchQuery query, Pattern compiledRegex) {
    EncodingFilter encodingFilter =
        query.encoding() == null ? EncodingFilter.ALL : query.encoding();
    Boolean definedFilter = query.defined();
    Integer minLength = query.minLength();
    String substring = query.query();
    boolean caseSensitive = query.caseSensitive();
    String loweredSubstring =
        substring != null && !caseSensitive ? substring.toLowerCase(Locale.ROOT) : substring;

    List<StringMatchResource> matched = new ArrayList<>();
    for (StringMatchResource item : candidates) {
      if (!encodingFilter.matches(item.encoding())) continue;
      if (definedFilter != null && item.defined() != definedFilter) continue;
      if (minLength != null && item.value().length() < minLength) continue;
      if (loweredSubstring != null && !loweredSubstring.isEmpty()) {
        String candidateValue =
            caseSensitive ? item.value() : item.value().toLowerCase(Locale.ROOT);
        if (!candidateValue.contains(loweredSubstring)) continue;
      }
      if (compiledRegex != null && !compiledRegex.matcher(item.value()).find()) {
        continue;
      }
      matched.add(item);
    }
    return matched;
  }

  private boolean isAnalysisRunning() {
    try {
      return analysisService.getStatus().status() == AnalysisResource.Status.RUNNING;
    } catch (UnsupportedOperationException ignored) {
      return false;
    }
  }

  private static Pattern compileRegex(String regex, boolean caseSensitive) {
    if (regex == null || regex.isEmpty()) {
      return null;
    }
    int flags = caseSensitive ? 0 : (Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE);
    return Pattern.compile(regex, flags);
  }

  private static long computeDeadlineNanos(Integer timeoutMs) {
    int clampedMs =
        timeoutMs == null ? AddressScanOptions.DEFAULT_TIMEOUT_MS : Math.max(1, timeoutMs);
    return System.nanoTime() + clampedMs * NANOS_PER_MILLISECOND;
  }

  private static AddressSet toAddressSet(Program program, AddressScanRanges.Resolved range) {
    Address end =
        range.end() != null ? range.end() : range.start().getAddressSpace().getMaxAddress();
    return new AddressSet(range.start(), end);
  }

  private static Address stepBackwardInBlock(MemoryBlock block, Address from, long delta) {
    long maxBack = from.subtract(block.getStart());
    if (maxBack <= 0 || maxBack <= delta) return block.getStart();
    return from.subtract(delta);
  }

  private static Address stepForwardInBlock(MemoryBlock block, Address from, long delta) {
    long maxFwd = block.getEnd().subtract(from);
    if (maxFwd <= 0 || maxFwd <= delta) return block.getEnd();
    try {
      return from.addNoWrap(delta);
    } catch (AddressOverflowException overflow) {
      return block.getEnd();
    }
  }

  private record RangeKey(String min, String max) {}

  private record Snapshot(
      List<StringMatchResource> entries,
      boolean complete,
      int totalIndexed,
      long modificationNumber,
      boolean rangeAlreadyApplied) {}
}
