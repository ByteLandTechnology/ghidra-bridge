package app.byteland.ghidra.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class PageTest {

  private record Candidate(String key, int id) {}

  @Test
  void selectorReturnsEmptyPageForNoCandidatesOrExhaustedCursor() {
    Page.Selector<String> empty = Page.selector(10, null);
    assertEquals(0, empty.retainedCount());
    Page<String> emptyPage = empty.finish();
    assertTrue(emptyPage.items().isEmpty());
    assertEquals(0, emptyPage.count());
    assertEquals(10, emptyPage.limit());
    assertNull(emptyPage.nextCursor());

    Page.Selector<String> exhausted = Page.selector(5, "k05");
    exhausted.offer("k01", "v1");
    exhausted.offer("k05", "v5");
    assertEquals(0, exhausted.retainedCount());
    Page<String> resumedPage = exhausted.finish();
    assertTrue(resumedPage.items().isEmpty());
    assertNull(resumedPage.nextCursor());
  }

  @Test
  void selectorHandlesExactLimitWithoutNextCursor() {
    AtomicInteger materialized = new AtomicInteger();
    Page.Selector<String> selector = Page.selector(3, null);
    selector.offer("c", "item-c");
    selector.offer("a", "item-a");
    selector.offer("b", "item-b");
    assertEquals(3, selector.retainedCount());

    Page<String> page =
        selector.finish(
            (item, key) -> {
              materialized.incrementAndGet();
              return key + ":" + item;
            });

    assertEquals(List.of("a:item-a", "b:item-b", "c:item-c"), page.items());
    assertEquals(3, page.count());
    assertEquals(3, page.limit());
    assertNull(page.nextCursor());
    assertEquals(3, materialized.get());
  }

  @Test
  void selectorRetainsAtMostLimitPlusOneAndMaterializesOnlyWinners() {
    AtomicInteger materialized = new AtomicInteger();
    Page.Selector<Integer> selector = Page.selector(3, null);
    for (int value = 100; value >= 1; value--) {
      selector.offer(String.format("k%03d", value), value);
      assertTrue(selector.retainedCount() <= 4);
    }
    assertEquals(4, selector.retainedCount());

    Page<String> page =
        selector.finish(
            (value, key) -> {
              materialized.incrementAndGet();
              return key + "=" + value;
            });

    assertEquals(List.of("k001=1", "k002=2", "k003=3"), page.items());
    assertEquals("k003", page.nextCursor());
    assertEquals(3, materialized.get());
  }

  @Test
  void selectorPreservesInsertionOrderForDuplicateKeysAndMatchesPaginate() {
    List<Candidate> unsorted =
        List.of(
            new Candidate("b", 1),
            new Candidate("a", 2),
            new Candidate("b", 3),
            new Candidate("a", 4),
            new Candidate("a", 5),
            new Candidate("c", 6),
            new Candidate("0", 7));

    List<Candidate> sorted = new ArrayList<>(unsorted);
    sorted.sort(Comparator.comparing(Candidate::key));

    for (int limit : List.of(0, 1, 2, 3, 4, 7, 2000)) {
      String expectedCursor = null;
      String actualCursor = null;
      while (true) {
        Page<Candidate> expected = Page.paginate(sorted, limit, expectedCursor, Candidate::key);
        Page.Selector<Candidate> selector = Page.selector(limit, actualCursor);
        for (Candidate candidate : unsorted) {
          selector.offer(candidate.key(), candidate);
        }
        Page<Candidate> actual = selector.finish();
        assertEquals(expected, actual);
        expectedCursor = expected.nextCursor();
        actualCursor = actual.nextCursor();
        if (expectedCursor == null) break;
      }
    }
  }

  @Test
  void selectorTreatsBlankCursorAsInitialPage() {
    Page.Selector<String> selector = Page.selector(2, "   ");
    selector.offer("b", "two");
    selector.offer("a", "one");
    selector.offer("c", "three");

    Page<String> page = selector.finish();
    assertEquals(List.of("one", "two"), page.items());
    assertEquals("b", page.nextCursor());
  }
}
