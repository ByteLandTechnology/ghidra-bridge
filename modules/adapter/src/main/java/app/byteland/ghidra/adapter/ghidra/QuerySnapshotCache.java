package app.byteland.ghidra.adapter.ghidra;

import app.byteland.ghidra.service.Page;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.LongSupplier;

/**
 * Bounded LRU and TTL cache of sorted compact key snapshots for cursor-paginated queries.
 *
 * <p>Entries are indexed by resource name, normalized filter components, and
 * {@code Program.getModificationNumber()}, and capped by both snapshot count and total key count.
 */
public final class QuerySnapshotCache {
  public static final int DEFAULT_MAX_ENTRIES = 32;
  public static final int DEFAULT_MAX_TOTAL_KEYS = 262_144;
  public static final Duration DEFAULT_TTL = Duration.ofSeconds(30);

  private final int maxEntries;
  private final int maxTotalKeys;
  private final long ttlNanos;
  private final LongSupplier nanoTime;
  private final Map<Key, Entry> entries;
  private int totalKeys;
  private Long lastModificationNumber;

  public QuerySnapshotCache() {
    this(DEFAULT_MAX_ENTRIES, DEFAULT_MAX_TOTAL_KEYS, DEFAULT_TTL, System::nanoTime);
  }

  public QuerySnapshotCache(
      int maxEntries, int maxTotalKeys, Duration ttl, LongSupplier nanoTime) {
    if (maxEntries < 0) {
      throw new IllegalArgumentException("maxEntries must not be negative");
    }
    if (maxTotalKeys < 0) {
      throw new IllegalArgumentException("maxTotalKeys must not be negative");
    }
    Objects.requireNonNull(ttl, "ttl");
    if (ttl.isNegative() || ttl.isZero()) {
      throw new IllegalArgumentException("ttl must be positive");
    }
    this.maxEntries = maxEntries;
    this.maxTotalKeys = maxTotalKeys;
    this.ttlNanos = ttl.toNanos();
    this.nanoTime = Objects.requireNonNull(nanoTime, "nanoTime");
    this.entries = new LinkedHashMap<>(16, 0.75f, true);
  }

  /**
   * Returns a cached sorted key snapshot on hit, or {@code null} on miss or expiration.
   */
  public synchronized String[] get(Key key) {
    Objects.requireNonNull(key, "key");
    long now = nanoTime.getAsLong();
    evictExpired(now);
    evictStaleModificationNumbers(key.modificationNumber());
    Entry entry = entries.get(key);
    return entry == null ? null : entry.keys;
  }

  /**
   * Stores an already-sorted key array if it fits within the cache entry and key caps.
   */
  public synchronized void put(Key key, String[] sortedKeys) {
    Objects.requireNonNull(key, "key");
    Objects.requireNonNull(sortedKeys, "sortedKeys");
    long now = nanoTime.getAsLong();
    evictExpired(now);
    evictStaleModificationNumbers(key.modificationNumber());

    Entry existing = entries.remove(key);
    if (existing != null) {
      totalKeys -= existing.keys.length;
    }

    if (maxEntries == 0 || sortedKeys.length > maxTotalKeys) {
      return;
    }

    while (!entries.isEmpty()
        && (entries.size() >= maxEntries || totalKeys + sortedKeys.length > maxTotalKeys)) {
      Iterator<Map.Entry<Key, Entry>> iterator = entries.entrySet().iterator();
      Map.Entry<Key, Entry> eldest = iterator.next();
      totalKeys -= eldest.getValue().keys.length;
      iterator.remove();
    }

    entries.put(key, new Entry(sortedKeys, now));
    totalKeys += sortedKeys.length;
  }

  public synchronized void clear() {
    entries.clear();
    totalKeys = 0;
    lastModificationNumber = null;
  }

  public synchronized int entryCount() {
    evictExpired(nanoTime.getAsLong());
    return entries.size();
  }

  public synchronized int totalKeyCount() {
    evictExpired(nanoTime.getAsLong());
    return totalKeys;
  }

  /**
   * Binary-searches {@code sortedKeys} for the first key strictly after {@code cursor}, resolves at
   * most {@code limit + 1} live objects, and materializes at most {@code limit} page items.
   */
  public static <L, R> Page<R> slice(
      String[] sortedKeys,
      int limit,
      String cursor,
      Function<String, L> resolver,
      Function<L, R> mapper) {
    Objects.requireNonNull(mapper, "mapper");
    return slice(sortedKeys, limit, cursor, resolver, (live, ignoredKey) -> mapper.apply(live));
  }

  /**
   * Binary-searches {@code sortedKeys} for the first key strictly after {@code cursor}, resolves at
   * most {@code limit + 1} live objects, and materializes at most {@code limit} page items with
   * their snapshot keys.
   */
  public static <L, R> Page<R> slice(
      String[] sortedKeys,
      int limit,
      String cursor,
      Function<String, L> resolver,
      BiFunction<L, String, R> mapper) {
    Objects.requireNonNull(sortedKeys, "sortedKeys");
    Objects.requireNonNull(resolver, "resolver");
    Objects.requireNonNull(mapper, "mapper");
    int clamped = Page.clampLimit(limit);
    int startIndex =
        cursor == null || cursor.isBlank() ? 0 : firstIndexAfter(sortedKeys, cursor);
    if (startIndex >= sortedKeys.length) {
      return Page.of(List.of(), clamped, null);
    }

    int capacity = Math.min(clamped, sortedKeys.length - startIndex);
    List<L> selectedLive = new ArrayList<>(capacity);
    List<String> selectedKeys = new ArrayList<>(capacity);
    String nextCursor = null;
    for (int i = startIndex; i < sortedKeys.length; i++) {
      String candidateKey = sortedKeys[i];
      L live = resolver.apply(candidateKey);
      if (live == null) {
        continue;
      }
      if (selectedLive.size() < clamped) {
        selectedLive.add(live);
        selectedKeys.add(candidateKey);
      } else {
        nextCursor = selectedKeys.getLast();
        break;
      }
    }

    List<R> items = new ArrayList<>(selectedLive.size());
    for (int i = 0; i < selectedLive.size(); i++) {
      items.add(mapper.apply(selectedLive.get(i), selectedKeys.get(i)));
    }
    return Page.of(items, clamped, nextCursor);
  }

  public static int firstIndexAfter(String[] sortedKeys, String cursor) {
    int index = Arrays.binarySearch(sortedKeys, cursor);
    if (index >= 0) {
      int next = index + 1;
      while (next < sortedKeys.length && sortedKeys[next].equals(cursor)) {
        next++;
      }
      return next;
    }
    return -index - 1;
  }

  private void evictExpired(long now) {
    Iterator<Map.Entry<Key, Entry>> iterator = entries.entrySet().iterator();
    while (iterator.hasNext()) {
      Map.Entry<Key, Entry> candidate = iterator.next();
      if (now - candidate.getValue().createdAtNanos >= ttlNanos) {
        totalKeys -= candidate.getValue().keys.length;
        iterator.remove();
      }
    }
  }

  private void evictStaleModificationNumbers(long currentModificationNumber) {
    if (lastModificationNumber != null && lastModificationNumber == currentModificationNumber) {
      return;
    }
    lastModificationNumber = currentModificationNumber;
    Iterator<Map.Entry<Key, Entry>> iterator = entries.entrySet().iterator();
    while (iterator.hasNext()) {
      Map.Entry<Key, Entry> candidate = iterator.next();
      if (candidate.getKey().modificationNumber() != currentModificationNumber) {
        totalKeys -= candidate.getValue().keys.length;
        iterator.remove();
      }
    }
  }

  /**
   * Composite cache key that records resource name, normalized filters, and program modification
   * number.
   */
  public record Key(String resource, List<String> filters, long modificationNumber) {
    public Key {
      Objects.requireNonNull(resource, "resource");
      Objects.requireNonNull(filters, "filters");
      filters = Collections.unmodifiableList(new ArrayList<>(filters));
    }

    public static Key of(String resource, long modificationNumber, String... normalizedFilters) {
      return new Key(resource, Arrays.asList(normalizedFilters), modificationNumber);
    }
  }

  private static final class Entry {
    private final String[] keys;
    private final long createdAtNanos;

    private Entry(String[] keys, long createdAtNanos) {
      this.keys = keys;
      this.createdAtNanos = createdAtNanos;
    }
  }
}
