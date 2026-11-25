package app.byteland.ghidra.adapter.ghidra.decompilation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.util.task.TaskMonitor;
import java.lang.reflect.Proxy;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class DecompilerPoolTest {
  @Test
  void boundedPoolCreatesSingleSharedObjectAndDisposesOnClose() {
    AtomicInteger created = new AtomicInteger();
    AtomicInteger decompiled = new AtomicInteger();
    AtomicInteger destroyed = new AtomicInteger();
    DecompInterface shared =
        new DecompInterface() {
          @Override
          public boolean setOptions(DecompileOptions xmlOptions) {
            return true;
          }

          @Override
          public int flushCache() {
            return 0;
          }

          @Override
          public DecompileResults decompileFunction(
              Function func, int timeoutSecs, TaskMonitor monitor) {
            decompiled.incrementAndGet();
            return null;
          }
        };
    Function function =
        (Function)
            Proxy.newProxyInstance(
                Function.class.getClassLoader(),
                new Class<?>[] {Function.class},
                (proxy, method, args) -> {
                  if (method.getName().equals("getProgram")) {
                    return null;
                  }
                  throw new AssertionError("Unexpected Function." + method.getName());
                });
    DecompilerPool pool =
        new DecompilerPool(
            1,
            () -> {
              created.incrementAndGet();
              return shared;
            },
            decompiler -> {
              assertSame(shared, decompiler);
              destroyed.incrementAndGet();
            });

    assertEquals(0, created.get());
    assertNull(pool.decompile(function, 1_000, false));
    assertNull(pool.decompile(function, 1_000, false));
    assertEquals(1, created.get());
    assertEquals(2, decompiled.get());
    assertEquals(0, destroyed.get());

    pool.close();
    assertEquals(1, destroyed.get());
  }
}
