package app.byteland.ghidra.service;

import java.util.ArrayList;
import java.util.List;
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
  /** Maximum item limit allowed per page. */
  public static final int MAX_LIMIT = 1000;

  /** Copies page items and validates count and limit bounds. */
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
   * Slices sorted items after an optional cursor into a single page.
   *
   * @param <T> resource item type
   * @param sortedItems items ordered by cursor key
   * @param limit maximum items to return
   * @param cursor optional last-seen cursor key
   * @param key function that extracts the cursor key from an item
   * @return paginated slice and next cursor token
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
   * Creates a page without scan progress metadata.
   *
   * @param <T> resource item type
   * @param items page items
   * @param limit requested page size limit
   * @param nextCursor optional next page cursor
   * @return constructed page
   */
  public static <T> Page<T> of(List<T> items, int limit, String nextCursor) {
    return new Page<>(items, items.size(), limit, nextCursor, null);
  }

  /**
   * Creates a page paired with bounded address scan progress metadata.
   *
   * @param <T> resource item type
   * @param items page items
   * @param limit requested page size limit
   * @param nextCursor optional next page cursor
   * @param scanProgress non-null scan progress summary
   * @return constructed page with scan metadata
   */
  public static <T> Page<T> scanned(
      List<T> items, int limit, String nextCursor, ScanProgress scanProgress) {
    if (scanProgress == null) throw new IllegalArgumentException("scanProgress is required");
    return new Page<>(items, items.size(), limit, nextCursor, scanProgress);
  }
}
