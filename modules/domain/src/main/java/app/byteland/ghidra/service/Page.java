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
  /** Maximum number of items permitted in one page. */
  public static final int MAX_LIMIT = 1000;

  /** Copies items into an immutable list and validates count and limit invariants. */
  public Page {
    items = List.copyOf(items);
    if (count != items.size()) throw new IllegalArgumentException("count must equal items size");
    if (limit < 1 || limit > MAX_LIMIT) {
      throw new IllegalArgumentException("limit must be in 1.." + MAX_LIMIT);
    }
  }

  /**
   * Clamps a requested page limit into {@code 1..MAX_LIMIT}.
   *
   * @param limit requested page size
   * @return clamped page size
   */
  public static int clampLimit(int limit) {
    return Math.max(1, Math.min(limit, MAX_LIMIT));
  }

  /**
   * Slices a pre-sorted list after an optional cursor key into one bounded page.
   *
   * @param <T> resource item type
   * @param sortedItems items ordered by {@code key} from low to high
   * @param limit maximum items to return
   * @param cursor exclusive resume key, or {@code null}
   * @param key function that extracts each item's sort key
   * @return single page of items with an optional next cursor
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
    return Page.of(items, clamped, next);
  }

  /**
   * Creates a bounded selector that retains one page of smallest keys after an optional cursor.
   *
   * @param <T> candidate item type
   * @param limit requested page limit
   * @param cursor exclusive resume key, or {@code null}
   * @return bounded page selector
   */
  public static <T> Selector<T> selector(int limit, String cursor) {
    return new Selector<>(limit, cursor);
  }

  /**
   * Creates a page without scan progress metadata.
   *
   * @param <T> resource item type
   * @param items page elements
   * @param limit requested page limit
   * @param nextCursor token for the next page, or {@code null}
   * @return page instance
   */
  public static <T> Page<T> of(List<T> items, int limit, String nextCursor) {
    return new Page<>(items, items.size(), limit, nextCursor, null);
  }

  /**
   * Creates a page produced by a bounded address scan.
   *
   * @param <T> resource item type
   * @param items matched elements in this scan step
   * @param limit requested item limit
   * @param nextCursor token to resume the scan, or {@code null} when complete
   * @param scanProgress non-null scan progress summary
   * @return scanned page instance
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
     * Evaluates a candidate key and item against the cursor and bounded retention heap.
     *
     * @param key candidate sort key
     * @param item candidate item value
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
     * Returns the number of candidate entries retained in the selector heap.
     *
     * @return retained candidate count
     */
    public int retainedCount() {
      return heap.size();
    }

    /**
     * Builds the selected page of items in sort-key order.
     *
     * @return selected page of items
     */
    public Page<T> finish() {
      return finish((item, ignoredKey) -> item);
    }

    /**
     * Maps each selected winner to an output item in sort-key order and builds the page.
     *
     * @param <R> mapped output item type
     * @param mapper function that converts each selected item
     * @return selected page of mapped items
     */
    public <R> Page<R> finish(Function<T, R> mapper) {
      Objects.requireNonNull(mapper, "mapper");
      return finish((item, ignoredKey) -> mapper.apply(item));
    }

    /**
     * Maps each selected winner and its sort key to an output item and builds the page.
     *
     * @param <R> mapped output item type
     * @param mapper function that converts each selected item and sort key
     * @return selected page of mapped items
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
      return Page.of(items, clamped, next);
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
