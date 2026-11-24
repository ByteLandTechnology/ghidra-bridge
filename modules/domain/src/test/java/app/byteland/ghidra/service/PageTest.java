package app.byteland.ghidra.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class PageTest {

  @Test
  void selectMatchesFullSortPaginateAcrossMultiPageSweep() {
    List<String> expectedSorted = new ArrayList<>();
    for (int i = 0; i < 250; i++) {
      expectedSorted.add(String.format("item-%04d", i));
    }
    List<String> shuffled = new ArrayList<>(expectedSorted);
    Collections.shuffle(shuffled, new Random(42L));

    String cursorA = null;
    String cursorB = null;
    int pageCount = 0;
    while (true) {
      AtomicInteger mappedCount = new AtomicInteger();
      Page<String> selected =
          Page.select(
              shuffled,
              17,
              cursorA,
              value -> value,
              value -> {
                mappedCount.incrementAndGet();
                return value.toUpperCase(java.util.Locale.ROOT);
              });
      Page<String> expected =
          Page.paginate(
              expectedSorted.stream()
                  .map(v -> v.toUpperCase(java.util.Locale.ROOT))
                  .toList(),
              17,
              cursorB,
              v -> v.toLowerCase(java.util.Locale.ROOT));

      assertEquals(expected.items(), selected.items());
      assertEquals(expected.nextCursor(), selected.nextCursor());
      assertEquals(selected.items().size(), mappedCount.get(), "mapper must run only on page slice");

      cursorA = selected.nextCursor();
      cursorB = expected.nextCursor();
      pageCount++;
      if (cursorA == null) {
        break;
      }
    }
    assertEquals(15, pageCount);
  }

  @Test
  void selectorBoundsRetentionAndHandlesExactLimitBoundary() {
    List<Integer> descending = new ArrayList<>();
    for (int i = 999; i >= 0; i--) {
      descending.add(i);
    }

    AtomicInteger materialized = new AtomicInteger();
    Page.Selector<Integer> selector = Page.selector(5, null);
    for (Integer candidate : descending) {
      String key = String.format("%04d", candidate);
      if (selector.acceptsKey(key)) {
        selector.offer(key, candidate);
      }
    }
    Page<String> firstPage =
        selector.finish(
            n -> {
              materialized.incrementAndGet();
              return "val:" + n;
            });

    assertEquals(List.of("val:0", "val:1", "val:2", "val:3", "val:4"), firstPage.items());
    assertEquals("0004", firstPage.nextCursor());
    assertEquals(5, materialized.get());

    // Exact remainder of 5 items on cursor "0994" -> 0995..0999 with null nextCursor.
    Page<Integer> exactLastPage =
        Page.select(descending, 5, "0994", n -> String.format("%04d", n));
    assertEquals(List.of(995, 996, 997, 998, 999), exactLastPage.items());
    assertNull(exactLastPage.nextCursor());
  }

  @Test
  void selectorPreservesInsertionOrderOnTiesAndHandlesEmptyInputs() {
    record Pair(String key, int id) {}

    List<Pair> candidates =
        List.of(
            new Pair("b", 1),
            new Pair("a", 2),
            new Pair("a", 3),
            new Pair("a", 4),
            new Pair("c", 5));

    List<Pair> sortedCopy = new ArrayList<>(candidates);
    sortedCopy.sort(Comparator.comparing(Pair::key));

    Page<Pair> selected = Page.select(candidates, 2, null, Pair::key);
    Page<Pair> expected = Page.paginate(sortedCopy, 2, null, Pair::key);
    assertEquals(expected, selected);

    Page<Pair> empty = Page.select(List.<Pair>of(), 10, null, Pair::key);
    assertEquals(List.of(), empty.items());
    assertNull(empty.nextCursor());
  }
}
