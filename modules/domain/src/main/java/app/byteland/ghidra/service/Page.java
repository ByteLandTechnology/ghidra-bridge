package app.byteland.ghidra.service;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.PriorityQueue;
import java.util.function.Function;

/**
 * Holds one page of items and metadata for the next page.
 *
 * @param <T> resource item type
 * @param items list of elements in this page
 * @param count total item count in this page
 * @param limit maximum item limit requested
 * @param nextCursor token for the next page
 * @param scanProgress optional scan progress metadata
 */
public record Page<T>(
    List<T> items, int count, int limit, String nextCursor, ScanProgress scanProgress) {
  public static final int MAX_LIMIT = 1000;

  public Page {
    items = List.copyOf(items);
    if (count != items.size()) throw new IllegalArgumentException("count must equal items size");
    if (limit < 1 || limit > MAX_LIMIT) {
      throw new IllegalArgumentException("limit must be in 1.." + MAX_LIMIT);
    }
  }

  public static int clampLimit(int limit) {
    return Math.max(1, Math.min(limit, MAX_LIMIT));
  }

  public static <T> Page<T> paginate(
      List<T> sortedItems, int limit, String cursor, Function<T, String> key) {
    int clamped = clampLimit(limit);
    boolean resuming = cursor != null && !cursor.isBlank();
    List<T> items = new ArrayList<>();
    String next = null;
    for (T item : sortedItems) {
      if (resuming && key.apply(item).compareTo(cursor) <= 0) continue;
      if (items.size() >= clamped) {
        next = key.apply(items.getLast());
        break;
      }
      items.add(item);
    }
    return Page.of(items, clamped, next);
  }

  /**
   * Selects one page from unordered candidates using bounded {@code limit + 1} selection.
   */
  public static <T> Page<T> select(
      Iterable<T> candidates, int limit, String cursor, Function<T, String> key) {
    return select(candidates, limit, cursor, key, Function.identity());
  }

  /**
   * Selects one page from unordered candidates using bounded {@code limit + 1} selection and maps
   * only the items in the returned page slice.
   */
  public static <T, R> Page<R> select(
      Iterable<T> candidates,
      int limit,
      String cursor,
      Function<T, String> key,
      Function<T, R> mapper) {
    Objects.requireNonNull(candidates, "candidates");
    Objects.requireNonNull(key, "key");
    Objects.requireNonNull(mapper, "mapper");
    Selector<T> selector = selector(limit, cursor);
    for (T candidate : candidates) {
      String candidateKey = key.apply(candidate);
      if (selector.acceptsKey(candidateKey)) {
        selector.offer(candidateKey, candidate);
      }
    }
    return selector.finish(mapper);
  }

  /**
   * Creates a bounded {@code limit + 1} selector for streaming unordered items.
   */
  public static <T> Selector<T> selector(int limit, String cursor) {
    return new Selector<>(limit, cursor);
  }

  public static <T> Page<T> of(List<T> items, int limit, String nextCursor) {
    return new Page<>(items, items.size(), limit, nextCursor, null);
  }

  public static <T> Page<T> scanned(
      List<T> items, int limit, String nextCursor, ScanProgress scanProgress) {
    if (scanProgress == null) throw new IllegalArgumentException("scanProgress is required");
    return new Page<>(items, items.size(), limit, nextCursor, scanProgress);
  }

  /**
   * Bounded {@code limit + 1} max-heap selector that skips full-collection sorting and defers item
   * materialization until the final slice is chosen.
   *
   * @param <T> unmaterialized candidate type
   */
  public static final class Selector<T> {
    private static final Comparator<KeyedEntry<?>> ASCENDING =
        Comparator.<KeyedEntry<?>, String>comparing(KeyedEntry::key)
            .thenComparingLong(KeyedEntry::sequence);
    private static final Comparator<KeyedEntry<?>> DESCENDING = ASCENDING.reversed();

    private final int clampedLimit;
    private final int maxRetained;
    private final String cursor;
    private final boolean resuming;
    private final PriorityQueue<KeyedEntry<T>> heap;
    private long sequence;

    private Selector(int limit, String cursor) {
      this.clampedLimit = clampLimit(limit);
      this.maxRetained = clampedLimit + 1;
      this.cursor = cursor;
      this.resuming = cursor != null && !cursor.isBlank();
      this.heap = new PriorityQueue<>(Math.min(maxRetained, 64), DESCENDING);
    }

    public int limit() {
      return clampedLimit;
    }

    public boolean acceptsKey(String candidateKey) {
      Objects.requireNonNull(candidateKey, "candidateKey");
      if (resuming && candidateKey.compareTo(cursor) <= 0) {
        return false;
      }
      if (heap.size() >= maxRetained) {
        KeyedEntry<T> largest = heap.peek();
        if (largest != null && candidateKey.compareTo(largest.key()) >= 0) {
          return false;
        }
      }
      return true;
    }

    public void offer(String candidateKey, T item) {
      if (!acceptsKey(candidateKey)) {
        return;
      }
      if (heap.size() >= maxRetained) {
        heap.poll();
      }
      heap.offer(new KeyedEntry<>(candidateKey, sequence++, item));
    }

    public Page<T> finish() {
      return finish(Function.identity());
    }

    public <R> Page<R> finish(Function<T, R> mapper) {
      Objects.requireNonNull(mapper, "mapper");
      if (heap.isEmpty()) {
        return Page.of(List.of(), clampedLimit, null);
      }
      List<KeyedEntry<T>> ordered = new ArrayList<>(heap);
      ordered.sort(ASCENDING);
      boolean hasMore = ordered.size() > clampedLimit;
      int count = hasMore ? clampedLimit : ordered.size();
      String nextCursor = hasMore && count > 0 ? ordered.get(count - 1).key() : null;
      List<R> items = new ArrayList<>(count);
      for (int i = 0; i < count; i++) {
        items.add(mapper.apply(ordered.get(i).item()));
      }
      return Page.of(items, clampedLimit, nextCursor);
    }
  }

  private record KeyedEntry<T>(String key, long sequence, T item) {}
}
