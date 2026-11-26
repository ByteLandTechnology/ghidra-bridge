package app.byteland.ghidra.adapter.ghidra.decompilation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class LeasePoolTest {

  @Test
  void decompilerPoolFactoryClampsBetweenTwoAndFourProcesses() {
    assertEquals(2, DecompilerPoolFactory.MIN_POOL_SIZE);
    assertEquals(4, DecompilerPoolFactory.MAX_POOL_SIZE);
    assertEquals(2, DecompilerPoolFactory.poolSize(1));
    assertEquals(2, DecompilerPoolFactory.poolSize(2));
    assertEquals(3, DecompilerPoolFactory.poolSize(3));
    assertEquals(4, DecompilerPoolFactory.poolSize(4));
    assertEquals(4, DecompilerPoolFactory.poolSize(8));
    assertEquals(4, DecompilerPoolFactory.poolSize(64));
  }

  @Test
  void poolCreatesResourcesLazilyCapsAtMaxSizeAndDestroysAllOnClose() throws Exception {
    AtomicInteger createdIds = new AtomicInteger();
    Set<Integer> destroyedIds = ConcurrentHashMap.newKeySet();

    LeasePool<Integer> pool = new LeasePool<>(4, createdIds::incrementAndGet, destroyedIds::add);

    // Lazy initialization: zero instances created until first acquire().
    assertEquals(0, createdIds.get());

    // Sequential reuse keeps created resource count at 1.
    for (int i = 0; i < 5; i++) {
      try (LeasePool.Lease<Integer> lease = pool.acquire()) {
        assertEquals(1, lease.value());
      }
    }
    assertEquals(1, createdIds.get());

    // Concurrent demand scales up to maxSize (4) and blocks 6 extra callers without exceeding 4.
    AtomicInteger activeLeases = new AtomicInteger();
    AtomicInteger maxActiveLeases = new AtomicInteger();
    CountDownLatch startLatch = new CountDownLatch(1);

    try (ExecutorService executor = Executors.newFixedThreadPool(10)) {
      List<Future<Integer>> futures = new ArrayList<>();
      for (int i = 0; i < 10; i++) {
        futures.add(
            executor.submit(() -> {
              startLatch.await();
              try (LeasePool.Lease<Integer> lease = pool.acquire()) {
                int current = activeLeases.incrementAndGet();
                maxActiveLeases.accumulateAndGet(current, Math::max);
                Thread.sleep(30L);
                activeLeases.decrementAndGet();
                return lease.value();
              }
            }));
      }
      startLatch.countDown();
      for (Future<Integer> future : futures) {
        int id = future.get(5, TimeUnit.SECONDS);
        assertTrue(id >= 1 && id <= 4);
      }
    }

    assertEquals(4, createdIds.get());
    assertEquals(4, maxActiveLeases.get());

    pool.close();
    assertEquals(Set.of(1, 2, 3, 4), destroyedIds);
    assertThrows(IllegalStateException.class, pool::acquire);
  }

  @Test
  void factoryFailureDoesNotLeakCapacityAndCloseDestroysInFlightLeaseOnRelease() {
    AtomicBoolean failFirst = new AtomicBoolean(true);
    AtomicInteger nextId = new AtomicInteger();
    Set<Integer> destroyed = ConcurrentHashMap.newKeySet();

    LeasePool<Integer> pool =
        new LeasePool<>(
            2,
            () -> {
              if (failFirst.getAndSet(false)) {
                throw new IllegalStateException("decompiler process failed to start");
              }
              return nextId.incrementAndGet();
            },
            destroyed::add);

    assertThrows(IllegalStateException.class, pool::acquire);
    assertEquals(0, nextId.get(), "Failed factory call must not create a resource");

    // Acquire both slots of the size-2 pool to prove the failed factory call released its slot.
    LeasePool.Lease<Integer> inFlight = pool.acquire();
    LeasePool.Lease<Integer> secondSlot = pool.acquire();
    assertEquals(1, inFlight.value());
    assertEquals(2, secondSlot.value());
    assertEquals(2, nextId.get());
    secondSlot.close();

    // Close pool while first lease is still held; idle slot drains now and active lease destroys on
    // close.
    pool.close();
    assertEquals(
        Set.of(2), destroyed, "Only idle resources should destroy before the active lease closes");

    inFlight.close();
    inFlight.close(); // Idempotent double-close.
    assertEquals(Set.of(1, 2), destroyed);
    assertThrows(IllegalStateException.class, inFlight::value);
  }
}
