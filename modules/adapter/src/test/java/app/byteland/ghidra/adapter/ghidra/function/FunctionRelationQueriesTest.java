package app.byteland.ghidra.adapter.ghidra.function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.GhidraTestSupport;
import app.byteland.ghidra.adapter.ghidra.QuerySnapshotCache;
import app.byteland.ghidra.adapter.ghidra.scan.CompositeCursor;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.function.FunctionCallResource;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.task.TaskMonitor;
import java.lang.reflect.Proxy;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class FunctionRelationQueriesTest {
  private static final GenericAddressSpace RAM =
      new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 0);

  @Test
  void defersMaterializationToPageSlicesAndCachesCallerSnapshots() {
    Fixture fixture = new Fixture(80);
    FunctionRelationQueries queries =
        new FunctionRelationQueries(fixture.session, fixture::resolve);

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

  @Test
  void getCallersAndCalleesSelectEntryKeysBeforeNamespaceOrProgramLookup() {
    AtomicInteger namespaceLookups = new AtomicInteger();
    AtomicInteger programLookups = new AtomicInteger();

    Function caller3 =
        relatedFunction(0x00403000L, "fn_c", "Ns::C", namespaceLookups, programLookups);
    Function caller1 =
        relatedFunction(0x00401000L, "fn_a", "Ns::A", namespaceLookups, programLookups);
    Function caller4 =
        relatedFunction(0x00404000L, "fn_d", "Ns::D", namespaceLookups, programLookups);
    Function caller2 =
        relatedFunction(0x00402000L, "fn_b", "Ns::B", namespaceLookups, programLookups);

    Set<Function> callers = new LinkedHashSet<>(List.of(caller3, caller1, caller4, caller2));
    Set<Function> callees = new LinkedHashSet<>(List.of(caller2, caller1));
    Function target = rootFunction(callers, callees);
    FunctionRelationQueries queries = new FunctionRelationQueries(raw -> target);

    Page<FunctionCallResource> page1 = queries.getCallers("ram:00400000", 2, null);
    assertEquals(
        List.of(
            new FunctionCallResource(
                "ram:00401000",
                "fn_a",
                null,
                FunctionCallResource.Direction.CALLERS,
                "Ns::A",
                null),
            new FunctionCallResource(
                "ram:00402000",
                "fn_b",
                null,
                FunctionCallResource.Direction.CALLERS,
                "Ns::B",
                null)),
        page1.items());
    assertEquals("ram:00402000", page1.nextCursor());
    assertEquals(2, namespaceLookups.get());
    assertEquals(2, programLookups.get());

    Page<FunctionCallResource> page2 =
        queries.getCallers("ram:00400000", 2, page1.nextCursor());
    assertEquals(
        List.of("ram:00403000", "ram:00404000"),
        page2.items().stream().map(FunctionCallResource::entry).toList());
    assertNull(page2.nextCursor());
    assertEquals(4, namespaceLookups.get());
    assertEquals(4, programLookups.get());

    Page<FunctionCallResource> exactLimitCallees = queries.getCallees("ram:00400000", 2, null);
    assertEquals(
        List.of("ram:00401000", "ram:00402000"),
        exactLimitCallees.items().stream().map(FunctionCallResource::entry).toList());
    assertEquals(
        FunctionCallResource.Direction.CALLEES,
        exactLimitCallees.items().getFirst().direction());
    assertNull(exactLimitCallees.nextCursor());

    Function emptyTarget = rootFunction(Set.of(), Set.of());
    Page<FunctionCallResource> empty =
        new FunctionRelationQueries(raw -> emptyTarget).getCallers("ram:00400000", 5, null);
    assertTrue(empty.items().isEmpty());
    assertNull(empty.nextCursor());
  }

  @Test
  void extractsMultiSiteCallReferencesOrderedByEntryAndCallSiteAndMaterializesOnlyWinners() {
    AtomicInteger namespaceLookups = new AtomicInteger();
    AtomicInteger programLookups = new AtomicInteger();

    Function helperA =
        relatedFunction(0x00401000L, "helper_a", "Ns::A", namespaceLookups, programLookups);
    Function helperB =
        relatedFunction(0x00402000L, "helper_b", "Ns::B", namespaceLookups, programLookups);
    Function indirectHelper =
        relatedFunction(0x00403000L, "helper_indirect", "Ns::C", namespaceLookups, programLookups);

    Address siteLate = RAM.getAddress(0x00400020L);
    Address siteEarly = RAM.getAddress(0x00400008L);
    Address siteB = RAM.getAddress(0x00400010L);

    AddressSet body = new AddressSet(RAM.getAddress(0x00400000L), RAM.getAddress(0x00400030L));
    List<Address> sourceAddrs = List.of(siteLate, siteEarly, siteB);

    Reference refA2 = callReference(siteLate, helperA.getEntryPoint(), RefType.UNCONDITIONAL_CALL);
    Reference refA1 = callReference(siteEarly, helperA.getEntryPoint(), RefType.UNCONDITIONAL_CALL);
    Reference refDataIgnored = callReference(siteEarly, helperB.getEntryPoint(), RefType.DATA);
    Reference refB = callReference(siteB, helperB.getEntryPoint(), RefType.COMPUTED_CALL);

    ReferenceManager refManager =
        (ReferenceManager)
            Proxy.newProxyInstance(
                ReferenceManager.class.getClassLoader(),
                new Class<?>[] {ReferenceManager.class},
                (proxy, method, args) ->
                    switch (method.getName()) {
                      case "getReferenceSourceIterator" -> addressIterator(sourceAddrs.iterator());
                      case "getReferencesFrom" -> {
                        Address from = (Address) args[0];
                        if (siteLate.equals(from)) yield new Reference[] {refA2};
                        if (siteEarly.equals(from)) yield new Reference[] {refA1, refDataIgnored};
                        if (siteB.equals(from)) yield new Reference[] {refB};
                        yield new Reference[0];
                      }
                      default -> throw new AssertionError(method.getName());
                    });
    FunctionManager fnManager =
        (FunctionManager)
            Proxy.newProxyInstance(
                FunctionManager.class.getClassLoader(),
                new Class<?>[] {FunctionManager.class},
                (proxy, method, args) -> {
                  if ("getFunctionAt".equals(method.getName())) {
                    Address addr = (Address) args[0];
                    if (helperA.getEntryPoint().equals(addr)) return helperA;
                    if (helperB.getEntryPoint().equals(addr)) return helperB;
                    return null;
                  }
                  throw new AssertionError(method.getName());
                });
    Program program =
        (Program)
            Proxy.newProxyInstance(
                Program.class.getClassLoader(),
                new Class<?>[] {Program.class},
                (proxy, method, args) ->
                    switch (method.getName()) {
                      case "getReferenceManager" -> refManager;
                      case "getFunctionManager" -> fnManager;
                      default -> throw new AssertionError(method.getName());
                    });
    Set<Function> calledSet = new LinkedHashSet<>(List.of(helperA, helperB, indirectHelper));
    Function callerFn =
        (Function)
            Proxy.newProxyInstance(
                Function.class.getClassLoader(),
                new Class<?>[] {Function.class},
                (proxy, method, args) ->
                    switch (method.getName()) {
                      case "getProgram" -> program;
                      case "getBody" -> body;
                      case "getCalledFunctions" -> calledSet;
                      default -> throw new AssertionError(method.getName());
                    });

    FunctionRelationQueries queries = new FunctionRelationQueries(raw -> callerFn);
    Page<FunctionCallResource> page1 = queries.getCallees("ram:00400000", 2, null);
    assertEquals(
        List.of(
            new FunctionCallResource(
                "ram:00401000",
                "helper_a",
                "ram:00400008",
                FunctionCallResource.Direction.CALLEES,
                "Ns::A",
                null),
            new FunctionCallResource(
                "ram:00401000",
                "helper_a",
                "ram:00400020",
                FunctionCallResource.Direction.CALLEES,
                "Ns::A",
                null)),
        page1.items());
    assertEquals(CompositeCursor.key("ram:00401000", "ram:00400020"), page1.nextCursor());
    assertEquals(1, namespaceLookups.get());

    Page<FunctionCallResource> page2 =
        queries.getCallees("ram:00400000", 2, page1.nextCursor());
    assertEquals(
        List.of(
            new FunctionCallResource(
                "ram:00402000",
                "helper_b",
                "ram:00400010",
                FunctionCallResource.Direction.CALLEES,
                "Ns::B",
                null),
            new FunctionCallResource(
                "ram:00403000",
                "helper_indirect",
                null,
                FunctionCallResource.Direction.CALLEES,
                "Ns::C",
                null)),
        page2.items());
    assertNull(page2.nextCursor());
    assertEquals(3, namespaceLookups.get());
  }

  private static AddressIterator addressIterator(Iterator<Address> iterator) {
    return (AddressIterator)
        Proxy.newProxyInstance(
            AddressIterator.class.getClassLoader(),
            new Class<?>[] {AddressIterator.class},
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "hasNext" -> iterator.hasNext();
                  case "next" -> iterator.next();
                  case "iterator" -> (AddressIterator) proxy;
                  default -> throw new AssertionError(method.getName());
                });
  }

  private static Reference callReference(Address from, Address to, RefType refType) {
    return (Reference)
        Proxy.newProxyInstance(
            Reference.class.getClassLoader(),
            new Class<?>[] {Reference.class},
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "getFromAddress" -> from;
                  case "getToAddress" -> to;
                  case "getReferenceType" -> refType;
                  default -> throw new AssertionError(method.getName());
                });
  }

  @Test
  void concurrentProgramDbReadsResolveCallersDemangleCppNamesAndInvalidateOnProgramSwitch()
      throws Exception {
    GhidraTestSupport.x64Language();
    ClassSearcher.search(TaskMonitor.DUMMY);
    try (GhidraTestSupport.ProgramHolder primary =
            GhidraTestSupport.createX64Program("fn-callers-primary");
        GhidraTestSupport.ProgramHolder secondary =
            GhidraTestSupport.createX64Program("fn-callers-secondary")) {
      primary.inTransaction(
          program -> {
            try {
              program.setExecutableFormat("Executable and Linking Format (ELF)");
              AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
              Address targetAddr = space.getAddress(0x00401000L);
              program
                  .getFunctionManager()
                  .createFunction(
                      "target_fn",
                      targetAddr,
                      new AddressSet(targetAddr, targetAddr.add(3)),
                      SourceType.USER_DEFINED);
              for (int i = 0; i < 6; i++) {
                Address callerAddr = space.getAddress(0x00401100L + (i * 0x20L));
                String fnName = "caller" + i;
                String mangledName = "_ZN3pkg" + fnName.length() + fnName + "Ei";
                program
                    .getFunctionManager()
                    .createFunction(
                        mangledName,
                        callerAddr,
                        new AddressSet(callerAddr, callerAddr.add(7)),
                        SourceType.USER_DEFINED);
                program
                    .getReferenceManager()
                    .addMemoryReference(
                        callerAddr,
                        targetAddr,
                        RefType.UNCONDITIONAL_CALL,
                        SourceType.USER_DEFINED,
                        0);
              }
            } catch (Exception error) {
              throw new RuntimeException(error);
            }
          });

      AtomicReference<Program> activeProgram = new AtomicReference<>(primary.program());
      GhidraScript poisonScript =
          new GhidraScript() {
            {
              this.monitor =
                  (TaskMonitor)
                      Proxy.newProxyInstance(
                          TaskMonitor.class.getClassLoader(),
                          new Class<?>[] {TaskMonitor.class},
                          (proxy, method, args) -> {
                            throw new AssertionError("read touched monitor: " + method.getName());
                          });
            }

            @Override
            protected void run() {}

            @Override
            public Program getCurrentProgram() {
              return activeProgram.get();
            }
          };

      GhidraSession session = new GhidraSession(poisonScript);
      FunctionServiceImpl service = new FunctionServiceImpl(session);

      CountDownLatch start = new CountDownLatch(1);
      try (ExecutorService pool = Executors.newFixedThreadPool(8)) {
        List<Future<List<FunctionCallResource>>> readers = new ArrayList<>();
        for (int t = 0; t < 8; t++) {
          readers.add(
              pool.submit(
                  () -> {
                    start.await();
                    List<FunctionCallResource> all = new ArrayList<>();
                    String cursor = null;
                    while (true) {
                      Page<FunctionCallResource> page =
                          service.getCallers("0x00401000", 2, cursor);
                      all.addAll(page.items());
                      cursor = page.nextCursor();
                      if (cursor == null) break;
                    }
                    return all;
                  }));
        }
        start.countDown();
        for (Future<List<FunctionCallResource>> reader : readers) {
          List<FunctionCallResource> callers = reader.get(15, TimeUnit.SECONDS);
          assertEquals(6, callers.size());
          assertEquals("_ZN3pkg7caller0Ei", callers.getFirst().name());
          assertTrue(callers.getFirst().demangledName().contains("pkg::caller0(int)"));
        }
      }
      assertEquals(1, session.querySnapshots().entryCount());

      // Program switch clears cached snapshots even before any new modification occurs.
      activeProgram.set(secondary.program());
      assertEquals(0, session.querySnapshots().entryCount());
    }
  }

  private static Function rootFunction(Set<Function> callers, Set<Function> callees) {
    return (Function)
        Proxy.newProxyInstance(
            Function.class.getClassLoader(),
            new Class<?>[] {Function.class},
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "getCallingFunctions" -> callers;
                  case "getCalledFunctions" -> callees;
                  case "getProgram" -> null;
                  default -> throw new AssertionError(method.getName());
                });
  }

  private static Function relatedFunction(
      long offset,
      String name,
      String namespaceName,
      AtomicInteger namespaceLookups,
      AtomicInteger programLookups) {
    Address entry = RAM.getAddress(offset);
    Namespace namespace =
        (Namespace)
            Proxy.newProxyInstance(
                Namespace.class.getClassLoader(),
                new Class<?>[] {Namespace.class},
                (proxy, method, args) -> {
                  if ("getName".equals(method.getName())) return namespaceName;
                  throw new AssertionError(method.getName());
                });
    return (Function)
        Proxy.newProxyInstance(
            Function.class.getClassLoader(),
            new Class<?>[] {Function.class},
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "getEntryPoint" -> entry;
                  case "getName" -> name;
                  case "getParentNamespace" -> {
                    namespaceLookups.incrementAndGet();
                    yield namespace;
                  }
                  case "getProgram" -> {
                    programLookups.incrementAndGet();
                    yield null;
                  }
                  case "hashCode" -> System.identityHashCode(proxy);
                  case "equals" -> proxy == args[0];
                  default -> throw new AssertionError(method.getName());
                });
  }

  private static final class Fixture {
    final GenericAddressSpace ram =
        new GenericAddressSpace("ram", 64, GenericAddressSpace.TYPE_RAM, 0);
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
        callers.removeIf(
            existing -> AddressUtil.canonicalAddress(existing.getEntryPoint()).equals(key));
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
