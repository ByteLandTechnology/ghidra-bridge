package app.byteland.ghidra.adapter.ghidra.decompilation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

import ghidra.app.decompiler.DecompInterface;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class DecompilerPoolTest {
  @Test
  void boundedPoolCreatesSingleSharedInstanceAndDisposesOnClose() {
    AtomicInteger created = new AtomicInteger();
    AtomicInteger destroyed = new AtomicInteger();
    DecompInterface shared = new DecompInterface();
    DecompilerPool pool =
        new DecompilerPool(
            1,
            () -> {
              created.incrementAndGet();
              return shared;
            },
            instance -> {
              assertSame(shared, instance);
              destroyed.incrementAndGet();
            });

    assertEquals(1, pool.maxSize());
    assertEquals(0, pool.createdCount());
    pool.close();
    assertEquals(0, created.get());
    assertEquals(0, destroyed.get());
  }
}
