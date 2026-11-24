package app.byteland.ghidra.adapter.ghidra;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import app.byteland.ghidra.service.Page;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

class QuerySnapshotCacheTest {

  @Test
  void cachesSnapshotsAndEvictsLeastRecentlyUsedByEntryCountAndKeyCap() {
    AtomicLong clock = new AtomicLong(1_000L);
    QuerySnapshotCache cache =
        new QuerySnapshotCache(2, 6, Duration.ofSeconds(30), clock::get);

    QuerySnapshotCache.Key k1 = QuerySnapshotCache.Key.of("data_type", 1L, "", null, null);
    QuerySnapshotCache.Key k2 = QuerySnapshotCache.Key.of("data_type", 1L, "foo", "/", "STRUCT");
    QuerySnapshotCache.Key k3 = QuerySnapshotCache.Key.of("reference", 1L, "to", "ram:0010", null);

    cache.put(k1, new String[] {"a", "b", "c"});
    cache.put(k2, new String[] {"d", "e"});
    assertEquals(2, cache.entryCount());
    assertEquals(5, cache.totalKeyCount());

    // Touch k1 so k2 becomes least-recently-used.
    assertArrayEquals(new String[] {"a", "b", "c"}, cache.get(k1));

    // Add k3 (2 keys) to exceed maxEntries=2 and totalKeys=6, which evicts k2 first.
    cache.put(k3, new String[] {"x", "y"});
    assertNull(cache.get(k2));
    assertArrayEquals(new String[] {"a", "b", "c"}, cache.get(k1));
    assertArrayEquals(new String[] {"x", "y"}, cache.get(k3));
    assertEquals(2, cache.entryCount());
    assertEquals(5, cache.totalKeyCount());

    // Add a 5-key snapshot to trigger eviction by maxTotalKeys=6 when maxEntries=2.
    QuerySnapshotCache.Key k4 = QuerySnapshotCache.Key.of("function_call", 1L, "ram:0020", "callers");
    cache.put(k4, new String[] {"1", "2", "3", "4", "5"});
    assertNull(cache.get(k1));
    assertNull(cache.get(k3));
    assertArrayEquals(new String[] {"1", "2", "3", "4", "5"}, cache.get(k4));
    assertEquals(1, cache.entryCount());
    assertEquals(5, cache.totalKeyCount());

    // Snapshot larger than maxTotalKeys=6 is never retained.
    QuerySnapshotCache.Key huge = QuerySnapshotCache.Key.of("data_type", 1L, "huge", null, null);
    cache.put(huge, new String[] {"1", "2", "3", "4", "5", "6", "7"});
    assertNull(cache.get(huge));
    assertArrayEquals(new String[] {"1", "2", "3", "4", "5"}, cache.get(k4));
  }

  @Test
  void expiresEntriesAfterTtlAndPurgesStaleModificationNumbers() {
    AtomicLong clock = new AtomicLong(0L);
    QuerySnapshotCache cache =
        new QuerySnapshotCache(8, 100, Duration.ofSeconds(10), clock::get);

    QuerySnapshotCache.Key mod1 = QuerySnapshotCache.Key.of("data_type", 10L, "", null, null);
    cache.put(mod1, new String[] {"/a", "/b"});
    assertArrayEquals(new String[] {"/a", "/b"}, cache.get(mod1));

    // Advance clock below TTL to retain entry.
    clock.addAndGet(Duration.ofSeconds(9).toNanos());
    assertArrayEquals(new String[] {"/a", "/b"}, cache.get(mod1));

    // Advance clock to TTL to expire entry and reset key count.
    clock.addAndGet(Duration.ofSeconds(1).toNanos());
    assertNull(cache.get(mod1));
    assertEquals(0, cache.entryCount());
    assertEquals(0, cache.totalKeyCount());

    // Modification number bump evicts snapshots from prior modification numbers.
    cache.put(mod1, new String[] {"/a", "/b", "/c"});
    assertEquals(3, cache.totalKeyCount());

    QuerySnapshotCache.Key mod2 = QuerySnapshotCache.Key.of("data_type", 11L, "", null, null);
    assertNull(cache.get(mod2));
    assertEquals(0, cache.entryCount());
    assertEquals(0, cache.totalKeyCount());
  }

  @Test
  void distinguishesNullEmptyAndSlashFiltersAndSlicesWithBinarySearch() {
    QuerySnapshotCache.Key anyCategory = QuerySnapshotCache.Key.of("data_type", 1L, "", null, null);
    QuerySnapshotCache.Key rootCategory = QuerySnapshotCache.Key.of("data_type", 1L, "", "/", null);
    QuerySnapshotCache.Key blankCategory = QuerySnapshotCache.Key.of("data_type", 1L, "", "", null);
    assertNotEquals(anyCategory, rootCategory);
    assertNotEquals(anyCategory, blankCategory);
    assertNotEquals(rootCategory, blankCategory);

    String[] sortedKeys = {"k01", "k02", "k03", "k04", "k05", "k06"};
    Map<String, Integer> liveObjects =
        Map.of("k01", 1, "k02", 2, "k04", 4, "k05", 5, "k06", 6); // k03 is absent
    AtomicInteger resolvedCount = new AtomicInteger();
    AtomicInteger mappedCount = new AtomicInteger();

    Page<String> page =
        QuerySnapshotCache.slice(
            sortedKeys,
            2,
            "k01",
            key -> {
              resolvedCount.incrementAndGet();
              return liveObjects.get(key);
            },
            val -> {
              mappedCount.incrementAndGet();
              return "item-" + val;
            });

    // Starts at k02, skips absent k03, selects k02 and k04, and checks k05 to set nextCursor="k04".
    assertEquals(List.of("item-2", "item-4"), page.items());
    assertEquals("k04", page.nextCursor());
    assertEquals(4, resolvedCount.get());
    assertEquals(2, mappedCount.get(), "mapper must never discard records");
  }
}
