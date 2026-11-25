package app.byteland.ghidra.service;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.PriorityQueue;
import java.util.function.BiFunction;
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
  /** Maximum number of items permitted in a single page. */
  public static final int MAX_LIMIT = 1000;

  /**
   * Defensively copies {@code items} and validates count and page-limit bounds.
   */
  public Page {
    items = List.copyOf(items);
    if (count != items.size()) throw new IllegalArgumentException("count must equal items size");
    if (limit < 1 || limit > MAX_LIMIT) {
      throw new IllegalArgumentException("limit must be in 1.." + MAX_LIMIT);
    }
  }

  /**
   * Clamps {@code limit} to the valid range {@code 1..MAX_LIMIT}.
   *
   * @param limit requested page size
   * @return clamped page size in {@code 1..MAX_LIMIT}
   */
  public static int clampLimit(int limit) {
    return Math.max(1, Math.min(limit, MAX_LIMIT));
  }

  /**
   * Slices a pre-sorted list after {@code cursor} into one bounded {@link Page}.
   *
   * @param <T> item type
   * @param sortedItems items ordered ascending by {@code key}
   * @param limit requested page size
   * @param cursor exclusive resumption key, or {@code null} for the first page
   * @param key function extracting the sort/cursor key for each item
   * @return page of matching items and optional continuation cursor
   */
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
    return of(items, clamped, next);
  }

  /**
   * Creates a bounded top-K selector that retains one page of items ordered after {@code cursor}.
   *
   * @param <T> candidate item type
   * @param limit requested page size
   * @param cursor exclusive resumption key, or {@code null} for the first page
   * @return bounded {@link Selector} instance
   */
  public static <T> Selector<T> selector(int limit, String cursor) {
    return new Selector<>(limit, cursor);
  }

  /**
   * Creates a {@link Page} without scan progress metadata.
   *
   * @param <T> item type
   * @param items page items
   * @param limit effective page size limit
   * @param nextCursor continuation cursor key, or {@code null} when exhausted
   * @return constructed {@link Page}
   */
  public static <T> Page<T> of(List<T> items, int limit, String nextCursor) {
    return new Page<>(items, items.size(), limit, nextCursor, null);
  }

  /**
   * Creates a {@link Page} carrying cooperative {@link ScanProgress} metadata.
   *
   * @param <T> item type
   * @param items page items
   * @param limit effective page size limit
   * @param nextCursor continuation cursor key, or {@code null} when complete
   * @param scanProgress non-null scan progress snapshot
   * @return constructed {@link Page}
   */
  public static <T> Page<T> scanned(
      List<T> items, int limit, String nextCursor, ScanProgress scanProgress) {
    if (scanProgress == null) throw new IllegalArgumentException("scanProgress is required");
    return new Page<>(items, items.size(), limit, nextCursor, scanProgress);
  }

  /**
   * Selects one page of smallest keys after a cursor in a bounded priority queue.
   *
   * @param <T> candidate item type
   */
  public static final class Selector<T> {
    private static final int INITIAL_CAPACITY = 32;

    private final int clamped;
    private final int maxRetained;
    private final String cursor;
    private final boolean resuming;
    private final PriorityQueue<Keyed<T>> heap;
    private long sequence;

    private Selector(int limit, String cursor) {
      this.clamped = clampLimit(limit);
      this.maxRetained = this.clamped + 1;
      this.resuming = cursor != null && !cursor.isBlank();
      this.cursor = this.resuming ? cursor : null;
      this.heap =
          new PriorityQueue<>(
              Math.min(this.maxRetained, INITIAL_CAPACITY), Keyed.maxOrder());
    }

    /**
     * Offers a candidate item keyed by {@code key} into the bounded selection heap.
     *
     * @param key non-null sort and cursor key
     * @param item candidate item associated with {@code key}
     */
    public void offer(String key, T item) {
      Objects.requireNonNull(key, "key");
      if (resuming && key.compareTo(cursor) <= 0) return;
      long order = sequence++;
      if (heap.size() == maxRetained) {
        Keyed<T> largest = heap.peek();
        if (largest != null && key.compareTo(largest.key()) >= 0) return;
        heap.poll();
      }
      heap.offer(new Keyed<>(key, order, item));
    }

    /**
     * Returns the number of candidates currently retained in the bounded heap.
     *
     * @return retained candidate count
     */
    public int retainedCount() {
      return heap.size();
    }

    /**
     * Produces the sorted {@link Page} of winning items without transformation.
     *
     * @return sorted page of selected items
     */
    public Page<T> finish() {
      return finish((item, ignoredKey) -> item);
    }

    /**
     * Produces the sorted {@link Page} after transforming each winning item with {@code mapper}.
     *
     * @param <R> mapped output item type
     * @param mapper function mapping winning items to output items
     * @return sorted page of mapped items
     */
    public <R> Page<R> finish(Function<T, R> mapper) {
      Objects.requireNonNull(mapper, "mapper");
      return finish((item, ignoredKey) -> mapper.apply(item));
    }

    /**
     * Produces the sorted {@link Page} after transforming each winning item and its key.
     *
     * @param <R> mapped output item type
     * @param mapper function mapping each winning item and sort key to an output item
     * @return sorted page of mapped items
     */
    public <R> Page<R> finish(BiFunction<T, String, R> mapper) {
      Objects.requireNonNull(mapper, "mapper");
      List<Keyed<T>> winners = new ArrayList<>(heap);
      winners.sort(Keyed.minOrder());
      boolean hasMore = winners.size() > clamped;
      int pageCount = hasMore ? clamped : winners.size();
      String next = hasMore ? winners.get(pageCount - 1).key() : null;
      List<R> items = new ArrayList<>(pageCount);
      for (int index = 0; index < pageCount; index++) {
        Keyed<T> winner = winners.get(index);
        items.add(mapper.apply(winner.item(), winner.key()));
      }
      return of(items, clamped, next);
    }
  }

  private record Keyed<T>(String key, long sequence, T item) {
    private static <T> Comparator<Keyed<T>> minOrder() {
      return (left, right) -> {
        int byKey = left.key.compareTo(right.key);
        return byKey != 0 ? byKey : Long.compare(left.sequence, right.sequence);
      };
    }

    private static <T> Comparator<Keyed<T>> maxOrder() {
      return (left, right) -> {
        int byKey = right.key.compareTo(left.key);
        return byKey != 0 ? byKey : Long.compare(right.sequence, left.sequence);
      };
    }
  }
}
