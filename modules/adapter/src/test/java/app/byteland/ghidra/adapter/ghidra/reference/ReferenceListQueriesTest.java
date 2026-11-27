package app.byteland.ghidra.adapter.ghidra.reference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.JsonUtil;
import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.QuerySnapshotCache;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.reference.ReferenceResource;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.DefaultAddressFactory;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import java.lang.reflect.Proxy;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

class ReferenceListQueriesTest {
  private static final GenericAddressSpace RAM =
      new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 0);

  private static final class TestScript extends GhidraScript {
    private TestScript(Program program) {
      set(program, TaskMonitor.DUMMY);
    }

    @Override
    protected void run() {}
  }

  @Test
  void streamsOverFourThousandIncomingReferencesPreservesEncodedOrderAndCachesSnapshots() {
    // 5,005 incoming references (> 4,096 FlatProgramAPI cap) with negative operandIndex (-1),
    // multi-digit operandIndex (10), and Address.EXT_FROM_ADDRESS.
    Fixture fixture = new Fixture(5_000);
    ReferenceListQueries queries = new ReferenceListQueries(fixture.session);

    // Single-page call at limit=25: bounded selection, zero snapshot retained, only 25 described.
    Page<ReferenceResource> firstPage =
        queries.listReferences(null, "ram:00400000", null, "to", 25, null);
    assertEquals(25, firstPage.items().size());
    assertEquals(0, fixture.cache.entryCount(), "page 1 must not retain snapshot");
    assertEquals(1, fixture.toIteratorOpens.get(), "streams from ReferenceManager.getReferencesTo");
    assertEquals(0, fixture.flatApiCalls.get(), "must not call FlatProgramAPI.getReferencesTo");
    assertEquals(25, fixture.describeCalls.get(), "zero discarded ReferenceResource records");

    // Full sweep over all 5,005 references at limit=500.
    fixture.describeCalls.set(0);
    fixture.toIteratorOpens.set(0);
    List<ReferenceResource> warmSweep = new ArrayList<>();
    String cursor = null;
    while (true) {
      Page<ReferenceResource> page =
          queries.listReferences(null, "ram:00400000", null, "to", 500, cursor);
      warmSweep.addAll(page.items());
      cursor = page.nextCursor();
      if (cursor == null) break;
    }

    assertEquals(5_005, warmSweep.size(), "all >4,096 incoming references streamed without cap");
    assertEquals(2, fixture.toIteratorOpens.get(), "only page 1 and page 2 scanned iterator");
    assertEquals(5_005, fixture.describeCalls.get(), "each reference described exactly once");

    // Verify exact ReferenceCursorKey.encoded sort order across the entire sweep.
    List<String> actualKeys =
        warmSweep.stream()
            .map(r -> JsonUtil.toJson(List.of(r.from(), r.to(), r.type(), r.operandIndex())))
            .toList();
    List<String> sortedKeys = new ArrayList<>(actualKeys);
    Collections.sort(sortedKeys);
    assertEquals(sortedKeys, actualKeys, "must preserve exact ReferenceCursorKey.encoded order");

    // Verify identical sweep when background analysis is active (stateless bounded selection).
    fixture.cache.clear();
    fixture.analyzing.set(true);
    List<ReferenceResource> analyzingSweep = new ArrayList<>();
    String bypassCursor = null;
    while (true) {
      Page<ReferenceResource> page =
          queries.listReferences(null, "ram:00400000", null, "to", 1_000, bypassCursor);
      assertEquals(0, fixture.cache.entryCount());
      analyzingSweep.addAll(page.items());
      bypassCursor = page.nextCursor();
      if (bypassCursor == null) break;
    }
    fixture.analyzing.set(false);
    assertEquals(warmSweep, analyzingSweep);

    // Program.getModificationNumber() increment invalidates cached snapshot.
    Page<ReferenceResource> initial =
        queries.listReferences(null, "ram:00400000", null, "to", 10, null);
    queries.listReferences(null, "ram:00400000", null, "to", 10, initial.nextCursor());
    assertEquals(1, fixture.cache.entryCount());
    fixture.modificationNumber.incrementAndGet();
    assertEquals(
        10,
        queries.listReferences(null, "ram:00400000", null, "to", 10, initial.nextCursor())
            .items()
            .size());
  }

  @Test
  void referenceCursorKeyEncodeMatchesJsonUtilForPlainAndEscapedValues() {
    List<ReferenceCursorKey> samples =
        List.of(
            new ReferenceCursorKey("ram:00100000", "ram:00200000", "UNCONDITIONAL_CALL", -1),
            new ReferenceCursorKey("Entry Point:entry point", "ram:00400000", "EXTERNAL", 0),
            new ReferenceCursorKey("space\"quote\\slash\t", "Stack:-0x10", "DATA\n", 10));
    for (ReferenceCursorKey sample : samples) {
      String expected =
          JsonUtil.toJson(List.of(sample.from(), sample.to(), sample.type(), sample.operandIndex()));
      assertEquals(expected, sample.encoded());
      assertEquals(sample, ReferenceCursorKey.decode(sample.encoded()));
    }
  }

  @Test
  void streamsIncomingReferencesPreservesJsonCursorOrderAndDescribesOnlyWinners() {
    Address anchor = RAM.getAddress(0x00405000L);
    Address callerA = RAM.getAddress(0x00401000L);
    Address callerB = RAM.getAddress(0x00402000L);
    AtomicInteger described = new AtomicInteger();
    AtomicInteger incomingStreams = new AtomicInteger();

    List<Reference> incoming =
        List.of(
            mockReference(callerB, anchor, RefType.UNCONDITIONAL_CALL, 0, true, described),
            mockReference(callerA, anchor, RefType.UNCONDITIONAL_CALL, 2, false, described),
            mockReference(callerA, anchor, RefType.UNCONDITIONAL_CALL, 10, false, described),
            mockReference(callerA, anchor, RefType.UNCONDITIONAL_CALL, -1, true, described),
            mockReference(callerA, anchor, RefType.DATA, 0, false, described));

    GhidraSession session = sessionWithReferences(incoming, new Reference[0], incomingStreams);
    ReferenceListQueries queries = new ReferenceListQueries(session);

    Page<ReferenceResource> page1 =
        queries.listReferences(null, "ram:00405000", "UNCONDITIONAL_CALL", "to", 2, null);
    assertEquals(1, incomingStreams.get());
    assertEquals(2, described.get());
    assertEquals(
        List.of(-1, 10), page1.items().stream().map(ReferenceResource::operandIndex).toList());
    assertEquals(
        "[\"ram:00401000\",\"ram:00405000\",\"UNCONDITIONAL_CALL\",10]", page1.nextCursor());

    Page<ReferenceResource> page2 =
        queries.listReferences(
            null, "ram:00405000", "UNCONDITIONAL_CALL", "to", 2, page1.nextCursor());
    assertEquals(2, incomingStreams.get());
    assertEquals(4, described.get());
    assertEquals(
        List.of("ram:00401000", "ram:00402000"),
        page2.items().stream().map(ReferenceResource::from).toList());
    assertEquals(
        List.of(2, 0), page2.items().stream().map(ReferenceResource::operandIndex).toList());
    assertNull(page2.nextCursor());
  }

  @Test
  void outgoingReferencesAndEmptyResultsWorkWithExactLimitBoundary() {
    Address from = RAM.getAddress(0x00401000L);
    Address to1 = RAM.getAddress(0x00402000L);
    Address to2 = RAM.getAddress(0x00403000L);
    AtomicInteger described = new AtomicInteger();

    Reference[] outgoing = {
      mockReference(from, to2, RefType.READ, 1, true, described),
      mockReference(from, to1, RefType.READ, 0, true, described)
    };
    ReferenceListQueries queries =
        new ReferenceListQueries(sessionWithReferences(List.of(), outgoing, new AtomicInteger()));

    Page<ReferenceResource> exact =
        queries.listReferences("ram:00401000", null, null, "from", 2, null);
    assertEquals(
        List.of("ram:00402000", "ram:00403000"),
        exact.items().stream().map(ReferenceResource::to).toList());
    assertNull(exact.nextCursor());
    assertEquals(2, described.get());

    Page<ReferenceResource> empty =
        queries.listReferences("ram:00401000", null, "WRITE", "from", 2, null);
    assertTrue(empty.items().isEmpty());
    assertNull(empty.nextCursor());
  }

  @Test
  void streamsMoreThan4096IncomingReferencesWithoutTruncation() {
    Address anchor = RAM.getAddress(0x00500000L);
    AtomicInteger described = new AtomicInteger();
    List<Reference> incoming = new ArrayList<>(5_000);
    for (int index = 5_000; index >= 1; index--) {
      incoming.add(
          mockReference(
              RAM.getAddress(0x00100000L + index * 4L),
              anchor,
              RefType.UNCONDITIONAL_CALL,
              0,
              true,
              described));
    }
    ReferenceListQueries queries =
        new ReferenceListQueries(sessionWithReferences(incoming, new Reference[0], new AtomicInteger()));

    Page<ReferenceResource> page =
        queries.listReferences(null, "ram:00500000", null, "to", 25, null);
    assertEquals(25, page.items().size());
    assertEquals("ram:00100004", page.items().getFirst().from());
    assertEquals("ram:00100064", page.items().getLast().from());
    assertEquals("[\"ram:00100064\",\"ram:00500000\",\"UNCONDITIONAL_CALL\",0]", page.nextCursor());
    assertEquals(25, described.get());
  }

  private static Reference mockReference(
      Address from,
      Address to,
      RefType type,
      int operandIndex,
      boolean primary,
      AtomicInteger described) {
    return (Reference)
        Proxy.newProxyInstance(
            Reference.class.getClassLoader(),
            new Class<?>[] {Reference.class},
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "getFromAddress" -> from;
                  case "getToAddress" -> to;
                  case "getReferenceType" -> type;
                  case "getOperandIndex" -> operandIndex;
                  case "isPrimary" -> {
                    described.incrementAndGet();
                    yield primary;
                  }
                  case "getSource" -> SourceType.ANALYSIS;
                  default -> throw new AssertionError(method.getName());
                });
  }

  private static GhidraSession sessionWithReferences(
      List<Reference> incoming, Reference[] outgoing, AtomicInteger incomingStreams) {
    AddressFactory factory = new DefaultAddressFactory(new AddressSpace[] {RAM});
    ReferenceManager manager =
        (ReferenceManager)
            Proxy.newProxyInstance(
                ReferenceManager.class.getClassLoader(),
                new Class<?>[] {ReferenceManager.class},
                (proxy, method, args) ->
                    switch (method.getName()) {
                      case "getReferencesTo" -> {
                        incomingStreams.incrementAndGet();
                        Iterator<Reference> iterator = incoming.iterator();
                        yield (ReferenceIterator)
                            Proxy.newProxyInstance(
                                ReferenceIterator.class.getClassLoader(),
                                new Class<?>[] {ReferenceIterator.class},
                                (iterProxy, iterMethod, iterArgs) ->
                                    switch (iterMethod.getName()) {
                                      case "hasNext" -> iterator.hasNext();
                                      case "next" -> iterator.next();
                                      case "iterator" -> (ReferenceIterator) iterProxy;
                                      default -> throw new AssertionError(iterMethod.getName());
                                    });
                      }
                      case "getReferencesFrom" -> outgoing;
                      default -> throw new AssertionError(method.getName());
                    });
    Program program =
        (Program)
            Proxy.newProxyInstance(
                Program.class.getClassLoader(),
                new Class<?>[] {Program.class},
                (proxy, method, args) ->
                    switch (method.getName()) {
                      case "getAddressFactory" -> factory;
                      case "getReferenceManager" -> manager;
                      default -> throw new AssertionError(method.getName());
                    });
    return new GhidraSession(new TestScript(program));
  }

  private static final class Fixture {
    final GenericAddressSpace ram =
        new GenericAddressSpace("ram", 64, GenericAddressSpace.TYPE_RAM, 0);
    final AddressFactory addressFactory = new DefaultAddressFactory(new AddressSpace[] {ram});
    final AtomicLong clockNanos = new AtomicLong(1_000L);
    final AtomicLong modificationNumber = new AtomicLong(1L);
    final AtomicBoolean analyzing = new AtomicBoolean(false);
    final AtomicInteger toIteratorOpens = new AtomicInteger();
    final AtomicInteger flatApiCalls = new AtomicInteger();
    final AtomicInteger describeCalls = new AtomicInteger();

    final Address target = ram.getAddress(0x00400000L);
    final List<Reference> incoming = new ArrayList<>();
    final Map<String, Reference> exactLookup = new HashMap<>();
    final QuerySnapshotCache cache =
        new QuerySnapshotCache(16, 100_000, Duration.ofSeconds(30), clockNanos::get);
    final GhidraSession session;

    Fixture(int regularCount) {
      for (int i = 0; i < regularCount; i++) {
        addIncoming(ram.getAddress(0x00100000L + (i * 4L)), RefType.UNCONDITIONAL_CALL, i % 3);
      }
      // Special operand indices and EXT_FROM_ADDRESS to verify exact encoded sort order and lookup.
      addIncoming(ram.getAddress(0x00090000L), RefType.DATA, -1);
      addIncoming(ram.getAddress(0x00090000L), RefType.DATA, 0);
      addIncoming(ram.getAddress(0x00090000L), RefType.DATA, 2);
      addIncoming(ram.getAddress(0x00090000L), RefType.DATA, 10);
      addIncoming(Address.EXT_FROM_ADDRESS, RefType.EXTERNAL_REF, 0);

      Collections.shuffle(incoming, new Random(99L));

      ReferenceManager refManager =
          (ReferenceManager)
              Proxy.newProxyInstance(
                  ReferenceManager.class.getClassLoader(),
                  new Class<?>[] {ReferenceManager.class},
                  (proxy, method, args) ->
                      switch (method.getName()) {
                        case "getReferencesTo" -> {
                          toIteratorOpens.incrementAndGet();
                          Iterator<Reference> it = incoming.iterator();
                          yield new ReferenceIterator() {
                            @Override
                            public boolean hasNext() {
                              return it.hasNext();
                            }

                            @Override
                            public Reference next() {
                              return it.next();
                            }

                            @Override
                            public Iterator<Reference> iterator() {
                              return this;
                            }
                          };
                        }
                        case "getReference" ->
                            exactLookup.get(
                                lookupKey((Address) args[0], (Address) args[1], (int) args[2]));
                        case "getReferencesFrom" -> new Reference[0];
                        default -> throw new UnsupportedOperationException(method.getName());
                      });

      Program program =
          (Program)
              Proxy.newProxyInstance(
                  Program.class.getClassLoader(),
                  new Class<?>[] {Program.class},
                  (proxy, method, args) ->
                      switch (method.getName()) {
                        case "getModificationNumber" -> modificationNumber.get();
                        case "getReferenceManager" -> refManager;
                        case "getAddressFactory" -> addressFactory;
                        case "parseAddress" -> new Address[0];
                        case "startTransaction" -> 1;
                        case "endTransaction" -> true;
                        default -> throw new UnsupportedOperationException(method.getName());
                      });

      GhidraScript script =
          new GhidraScript() {
            {
              this.currentProgram = program;
            }

            @Override
            protected void run() {}
          };
      this.session = new GhidraSession(script, cache, analyzing::get);
    }

    private void addIncoming(Address from, RefType refType, int opIndex) {
      Reference ref =
          (Reference)
              Proxy.newProxyInstance(
                  Reference.class.getClassLoader(),
                  new Class<?>[] {Reference.class},
                  (proxy, method, args) ->
                      switch (method.getName()) {
                        case "getFromAddress" -> from;
                        case "getToAddress" -> target;
                        case "getReferenceType" -> refType;
                        case "getOperandIndex" -> opIndex;
                        case "isPrimary" -> {
                          describeCalls.incrementAndGet();
                          yield true;
                        }
                        case "getSource" -> SourceType.ANALYSIS;
                        default -> throw new UnsupportedOperationException(method.getName());
                      });
      incoming.add(ref);
      exactLookup.put(lookupKey(from, target, opIndex), ref);
    }

    private static String lookupKey(Address from, Address to, int opIndex) {
      return AddressUtil.canonicalAddress(from)
          + "->"
          + AddressUtil.canonicalAddress(to)
          + "#"
          + opIndex;
    }
  }
}
