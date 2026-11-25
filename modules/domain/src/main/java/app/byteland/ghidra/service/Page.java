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
  /** Maximum number of items allowed in a single page. */
  public static final int MAX_LIMIT = 1000;

  /** Validates page invariants and freezes {@code items}. */
  public Page {
    items = List.copyOf(items);
    if (count != items.size()) throw new IllegalArgumentException("count must equal items size");
    if (limit < 1 || limit > MAX_LIMIT) {
      throw new IllegalArgumentException("limit must be in 1.." + MAX_LIMIT);
    }
  }

  /**
   * Clamps {@code limit} to {@code 1..MAX_LIMIT}.
   *
   * @param limit requested page limit
   * @return clamped page limit
   */
  public static int clampLimit(int limit) {
    return Math.max(1, Math.min(limit, MAX_LIMIT));
  }

  /**
   * Slices {@code sortedItems} after {@code cursor} into a single page of up to {@code limit}
   * items.
   *
   * @param <T> resource item type
   * @param sortedItems items already ordered by {@code key}
   * @param limit requested maximum page size
   * @param cursor exclusive lower-bound cursor key, or {@code null}
   * @param key function extracting the sort/cursor key from each item
   * @return resulting page slice
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
   * Creates a bounded top-K selector for streaming unsorted items after {@code cursor}.
   *
   * @param <T> candidate item type
   * @param limit requested page size
   * @param cursor exclusive lower-bound cursor key, or {@code null}
   * @return streaming page selector
   */
  public static <T> Selector<T> selector(int limit, String cursor) {
    return new Selector<>(limit, cursor);
  }

  /**
   * Creates a page without scan progress metadata.
   *
   * @param <T> resource item type
   * @param items page items
   * @param limit effective page limit
   * @param nextCursor next-page cursor key, or {@code null}
   * @return constructed page
   */
  public static <T> Page<T> of(List<T> items, int limit, String nextCursor) {
    return new Page<>(items, items.size(), limit, nextCursor, null);
  }

  /**
   * Creates a page carrying bounded address-scan progress metadata.
   *
   * @param <T> resource item type
   * @param items page items
   * @param limit effective page limit
   * @param nextCursor next-page cursor key, or {@code null}
   * @param scanProgress required scan progress metadata
   * @return constructed scanned page
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
     * Offers a candidate item and its sort key to the bounded selector.
     *
     * @param key lexicographic sort/cursor key
     * @param item candidate item
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
     * Returns the number of candidate items currently retained in the selector heap.
     *
     * @return retained candidate count
     */
    public int retainedCount() {
      return heap.size();
    }

    /**
     * Materializes the selected page without transforming items.
     *
     * @return ordered page of selected items
     */
    public Page<T> finish() {
      return finish((item, ignoredKey) -> item);
    }

    /**
     * Materializes the selected page, mapping each winning item with {@code mapper}.
     *
     * @param <R> mapped output item type
     * @param mapper function transforming each selected item
     * @return ordered page of mapped items
     */
    public <R> Page<R> finish(Function<T, R> mapper) {
      Objects.requireNonNull(mapper, "mapper");
      return finish((item, ignoredKey) -> mapper.apply(item));
    }

    /**
     * Materializes the selected page, mapping each winning item and its key with {@code mapper}.
     *
     * @param <R> mapped output item type
     * @param mapper function transforming each selected item and sort key
     * @return ordered page of mapped items
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
