package app.byteland.ghidra.adapter.ghidra;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertIterableEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.DefaultAddressFactory;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

class AddressUtilAndSessionReadTest {

  static final class PoisonReadScript extends GhidraScript {
    private final Program exposedProgram;

    PoisonReadScript(Program exposedProgram) {
      this.exposedProgram = exposedProgram;
      // Leave FlatProgramAPI.currentProgram null and install a poison monitor so any
      // FlatProgramAPI helper (toAddr, getReferencesTo, getBytes, getFunctionAfter) fails.
      this.monitor =
          proxy(
              ghidra.util.task.TaskMonitor.class,
              (method, args) -> {
                throw new AssertionError(
                    "Read path must not touch GhidraScript monitor: " + method);
              });
    }

    @Override
    protected void run() {}

    @Override
    public Program getCurrentProgram() {
      return exposedProgram;
    }
  }

  @Test
  void concurrentSessionReadsUseProgramManagersWithoutTouchingGhidraScriptHelpers()
      throws Exception {
    GenericAddressSpace ram = new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 0);
    AddressFactory addressFactory = new DefaultAddressFactory(new AddressSpace[] {ram}, ram);
    Address fn1Entry = ram.getAddress(0x00100000L);
    Address fn2Entry = ram.getAddress(0x00100040L);

    Function fn1 = functionProxy(fn1Entry, "fn_one");
    Function fn2 = functionProxy(fn2Entry, "fn_two");
    Reference sampleRef = proxy(Reference.class, (method, args) -> null);

    SymbolIterator emptySymbols =
        proxy(
            SymbolIterator.class,
            (method, args) -> "hasNext".equals(method) ? Boolean.FALSE : null);
    SymbolTable symbolTable =
        proxy(
            SymbolTable.class,
            (method, args) -> {
              if ("getSymbols".equals(method)) return emptySymbols;
              if ("getPrimarySymbol".equals(method)) return null;
              return null;
            });

    ReferenceManager referenceManager =
        proxy(
            ReferenceManager.class,
            (method, args) -> {
              if ("getReferencesFrom".equals(method)) {
                return new Reference[] {sampleRef};
              }
              if ("getReferencesTo".equals(method)) {
                Iterator<Reference> it = List.of(sampleRef).iterator();
                return proxy(
                    ReferenceIterator.class,
                    (m, a) ->
                        switch (m) {
                          case "hasNext" -> it.hasNext();
                          case "next" -> it.next();
                          default -> null;
                        });
              }
              return null;
            });

    Memory memory =
        proxy(
            Memory.class,
            (method, args) -> {
              if ("getBytes".equals(method)) {
                Address addr = (Address) args[0];
                byte[] dst = (byte[]) args[1];
                for (int i = 0; i < dst.length; i++) {
                  dst[i] = (byte) ((addr.getOffset() + i) & 0xff);
                }
                return dst.length;
              }
              return null;
            });

    Listing listing =
        proxy(
            Listing.class,
            (method, args) -> {
              if ("getFunctions".equals(method)) {
                Address start = (Address) args[0];
                List<Function> matching = new ArrayList<>();
                if (start.compareTo(fn1Entry) <= 0) matching.add(fn1);
                if (start.compareTo(fn2Entry) <= 0) matching.add(fn2);
                Iterator<Function> it = matching.iterator();
                return proxy(
                    FunctionIterator.class,
                    (m, a) ->
                        switch (m) {
                          case "hasNext" -> it.hasNext();
                          case "next" -> it.next();
                          default -> null;
                        });
              }
              return null;
            });

    Program program =
        proxy(
            Program.class,
            (method, args) ->
                switch (method) {
                  case "getAddressFactory" -> addressFactory;
                  case "getSymbolTable" -> symbolTable;
                  case "getReferenceManager" -> referenceManager;
                  case "getMemory" -> memory;
                  case "getListing" -> listing;
                  default -> null;
                });

    GhidraSession session = new GhidraSession(new PoisonReadScript(program));

    CountDownLatch start = new CountDownLatch(1);
    try (ExecutorService pool = Executors.newFixedThreadPool(20)) {
      List<Future<Void>> tasks = new ArrayList<>();
      for (int t = 0; t < 20; t++) {
        final int tid = t;
        tasks.add(
            pool.submit(() -> {
              start.await();
              for (int i = 0; i < 50; i++) {
                long offset = 0x00100000L + ((tid * 16L + i) & 0xffL);
                String hex = "0x" + Long.toHexString(offset);
                Address parsed = session.parseAddress(hex);
                assertEquals(offset, parsed.getOffset());
                assertEquals(
                    parsed, AddressUtil.parseAddress(program, "ram:" + Long.toHexString(offset)));

                byte[] bytes = session.readBytes(parsed, 4);
                assertArrayEquals(
                    new byte[] {
                      (byte) (offset & 0xff),
                      (byte) ((offset + 1) & 0xff),
                      (byte) ((offset + 2) & 0xff),
                      (byte) ((offset + 3) & 0xff)
                    },
                    bytes);

                assertIterableEquals(List.of(sampleRef), session.references(parsed, true));
                assertIterableEquals(List.of(sampleRef), session.references(parsed, false));

                assertSame(fn2, session.functionAfter(fn1));
                assertSame(fn2, session.functionAfter(fn1Entry));
                assertNull(session.functionAfter(fn2));
              }
              return null;
            }));
      }
      start.countDown();
      for (Future<Void> task : tasks) {
        task.get(10, TimeUnit.SECONDS);
      }
    }
  }

  private static Function functionProxy(Address entry, String name) {
    return proxy(
        Function.class,
        (method, args) ->
            switch (method) {
              case "getEntryPoint" -> entry;
              case "getName" -> name;
              default -> null;
            });
  }

  private interface Invocation {
    Object invoke(String method, Object[] args) throws Exception;
  }

  private static <T> T proxy(Class<T> type, Invocation handler) {
    return type.cast(
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (proxy, method, args) -> {
              if (method.getDeclaringClass() == Object.class) {
                return switch (method.getName()) {
                  case "toString" -> type.getSimpleName();
                  case "hashCode" -> System.identityHashCode(proxy);
                  case "equals" -> proxy == args[0];
                  default -> null;
                };
              }
              return handler.invoke(method.getName(), args);
            }));
  }
}
