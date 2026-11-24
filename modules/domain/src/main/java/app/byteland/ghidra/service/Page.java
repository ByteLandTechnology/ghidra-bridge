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
   * Selects one page of smallest keys after a cursor in a bounded {@code limit + 1} priority queue,
   * deferring item materialization until the final slice is chosen.
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
          new PriorityQueue<>(Math.min(this.maxRetained, INITIAL_CAPACITY), Keyed.maxOrder());
    }

    public int limit() {
      return clamped;
    }

    public int retainedCount() {
      return heap.size();
    }

    public boolean acceptsKey(String candidateKey) {
      Objects.requireNonNull(candidateKey, "candidateKey");
      if (resuming && candidateKey.compareTo(cursor) <= 0) {
        return false;
      }
      if (heap.size() >= maxRetained) {
        Keyed<T> largest = heap.peek();
        if (largest != null && candidateKey.compareTo(largest.key()) >= 0) {
          return false;
        }
      }
      return true;
    }

    public void offer(String key, T item) {
      Objects.requireNonNull(key, "key");
      if (!acceptsKey(key)) {
        return;
      }
      if (heap.size() >= maxRetained) {
        heap.poll();
      }
      heap.offer(new Keyed<>(key, sequence++, item));
    }

    public Page<T> finish() {
      return finish((item, ignoredKey) -> item);
    }

    public <R> Page<R> finish(Function<T, R> mapper) {
      Objects.requireNonNull(mapper, "mapper");
      return finish((item, ignoredKey) -> mapper.apply(item));
    }

    public <R> Page<R> finish(BiFunction<T, String, R> mapper) {
      Objects.requireNonNull(mapper, "mapper");
      if (heap.isEmpty()) {
        return Page.of(List.of(), clamped, null);
      }
      List<Keyed<T>> winners = new ArrayList<>(heap);
      winners.sort(Keyed.minOrder());
      boolean hasMore = winners.size() > clamped;
      int pageCount = hasMore ? clamped : winners.size();
      String next = hasMore && pageCount > 0 ? winners.get(pageCount - 1).key() : null;
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
