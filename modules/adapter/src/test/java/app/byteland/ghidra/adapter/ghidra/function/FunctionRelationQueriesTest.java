package app.byteland.ghidra.adapter.ghidra.function;

import static org.junit.jupiter.api.Assertions.assertEquals;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.QuerySnapshotCache;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.function.FunctionCallResource;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import java.lang.reflect.Proxy;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

class FunctionRelationQueriesTest {

  @Test
  void defersMaterializationToPageSlicesAndCachesCallerSnapshots() {
    Fixture fixture = new Fixture(80);
    FunctionRelationQueries queries = new FunctionRelationQueries(fixture.session, fixture::resolve);

    // Page 1 (cursor == null): bounded selection, zero snapshot retained, only 8 items materialized.
    Page<FunctionCallResource> p1 = queries.getCallers("ram:00100000", 8, null);
    assertEquals(8, p1.items().size());
    assertEquals("ram:00200000", p1.items().getFirst().entry());
    assertEquals("ram:00200007", p1.nextCursor());
    assertEquals(0, fixture.cache.entryCount());
    assertEquals(1, fixture.relationScans.get());
    assertEquals(8, fixture.materializedCalls.get(), "only page-slice functions materialized");

    // Sweep remaining 9 pages via cached snapshot.
    List<String> warmEntries = new ArrayList<>();
    warmEntries.addAll(p1.items().stream().map(FunctionCallResource::entry).toList());
    String cursor = p1.nextCursor();
    while (cursor != null) {
      Page<FunctionCallResource> page = queries.getCallers("ram:00100000", 8, cursor);
      warmEntries.addAll(page.items().stream().map(FunctionCallResource::entry).toList());
      cursor = page.nextCursor();
    }

    assertEquals(80, warmEntries.size());
    assertEquals(1, fixture.cache.entryCount());
    assertEquals(2, fixture.relationScans.get(), "only page 1 and first cursor page scanned");
    assertEquals(80, fixture.materializedCalls.get(), "zero discarded FunctionCallResource items");

    // Verify identical sweep when analysis bypasses snapshot caching.
    fixture.cache.clear();
    fixture.analyzing.set(true);
    List<String> bypassEntries = new ArrayList<>();
    String bypassCursor = null;
    while (true) {
      Page<FunctionCallResource> page = queries.getCallers("ram:00100000", 8, bypassCursor);
      assertEquals(0, fixture.cache.entryCount());
      bypassEntries.addAll(page.items().stream().map(FunctionCallResource::entry).toList());
      bypassCursor = page.nextCursor();
      if (bypassCursor == null) break;
    }
    fixture.analyzing.set(false);
    assertEquals(warmEntries, bypassEntries);

    // Program.getModificationNumber() bump invalidates cached snapshot and reflects new caller.
    queries.getCallers("ram:00100000", 8, p1.nextCursor());
    assertEquals(1, fixture.cache.entryCount());
    fixture.addCaller(0x00200008L, true);
    fixture.modificationNumber.incrementAndGet();

    Page<FunctionCallResource> refreshed = queries.getCallers("ram:00100000", 8, "ram:00200007");
    assertEquals("func_new_200008", refreshed.items().getFirst().name());
  }

  private static final class Fixture {
    final GenericAddressSpace ram = new GenericAddressSpace("ram", 64, GenericAddressSpace.TYPE_RAM, 0);
    final AtomicLong clockNanos = new AtomicLong(1_000L);
    final AtomicLong modificationNumber = new AtomicLong(1L);
    final AtomicBoolean analyzing = new AtomicBoolean(false);
    final AtomicInteger relationScans = new AtomicInteger();
    final AtomicInteger materializedCalls = new AtomicInteger();

    final Map<String, Function> functionsByEntry = new LinkedHashMap<>();
    final List<Function> callers = new ArrayList<>();
    final QuerySnapshotCache cache =
        new QuerySnapshotCache(16, 10_000, Duration.ofSeconds(30), clockNanos::get);
    final Program program;
    final GhidraSession session;

    Fixture(int callerCount) {
      Namespace globalNs =
          (Namespace)
              Proxy.newProxyInstance(
                  Namespace.class.getClassLoader(),
                  new Class<?>[] {Namespace.class},
                  (proxy, method, args) -> {
                    if ("getName".equals(method.getName())) {
                      materializedCalls.incrementAndGet();
                      return "Global";
                    }
                    throw new UnsupportedOperationException(method.getName());
                  });

      this.program =
          (Program)
              Proxy.newProxyInstance(
                  Program.class.getClassLoader(),
                  new Class<?>[] {Program.class},
                  (proxy, method, args) -> {
                    if ("getModificationNumber".equals(method.getName())) {
                      return modificationNumber.get();
                    }
                    throw new UnsupportedOperationException(method.getName());
                  });

      Address targetAddr = ram.getAddress(0x00100000L);
      Function target =
          (Function)
              Proxy.newProxyInstance(
                  Function.class.getClassLoader(),
                  new Class<?>[] {Function.class},
                  (proxy, method, args) ->
                      switch (method.getName()) {
                        case "getEntryPoint" -> targetAddr;
                        case "getName" -> "target";
                        case "getProgram" -> program;
                        case "getParentNamespace" -> globalNs;
                        case "getCallingFunctions" -> {
                          relationScans.incrementAndGet();
                          Set<Function> set = new LinkedHashSet<>(callers);
                          yield set;
                        }
                        case "getCalledFunctions" -> Set.of();
                        default -> throw new UnsupportedOperationException(method.getName());
                      });
      functionsByEntry.put(AddressUtil.canonicalAddress(targetAddr), target);

      for (int i = 0; i < callerCount; i++) {
        Address addr = ram.getAddress(0x00200000L + i);
        String name = String.format("caller_%04d", i);
        Function caller = buildFunction(addr, name, globalNs);
        functionsByEntry.put(AddressUtil.canonicalAddress(addr), caller);
        callers.add(caller);
      }
      Collections.shuffle(callers, new Random(19L));

      GhidraScript script =
          new GhidraScript() {
            @Override
            protected void run() {}

            @Override
            public Program getCurrentProgram() {
              return program;
            }
          };
      this.session = new GhidraSession(script, cache, analyzing::get);
    }

    void addCaller(long offset, boolean replace) {
      Namespace renamedNs =
          (Namespace)
              Proxy.newProxyInstance(
                  Namespace.class.getClassLoader(),
                  new Class<?>[] {Namespace.class},
                  (proxy, method, args) -> "Global");
      Address addr = ram.getAddress(offset);
      Function fn = buildFunction(addr, "func_new_" + Long.toHexString(offset), renamedNs);
      String key = AddressUtil.canonicalAddress(addr);
      if (replace) {
        callers.removeIf(existing -> AddressUtil.canonicalAddress(existing.getEntryPoint()).equals(key));
      }
      functionsByEntry.put(key, fn);
      callers.add(fn);
    }

    private Function buildFunction(Address entry, String name, Namespace ns) {
      return (Function)
          Proxy.newProxyInstance(
              Function.class.getClassLoader(),
              new Class<?>[] {Function.class},
              (proxy, method, args) ->
                  switch (method.getName()) {
                    case "getEntryPoint" -> entry;
                    case "getName" -> name;
                    case "getProgram" -> program;
                    case "getParentNamespace" -> ns;
                    case "equals" -> proxy == args[0];
                    case "hashCode" -> System.identityHashCode(proxy);
                    default -> throw new UnsupportedOperationException(method.getName());
                  });
    }

    Function resolve(String rawAddress) {
      Function fn = functionsByEntry.get(rawAddress);
      if (fn == null) throw new NoSuchElementException("not found: " + rawAddress);
      return fn;
    }
  }
}
