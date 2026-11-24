package app.byteland.ghidra.adapter.ghidra.reference;

import static org.junit.jupiter.api.Assertions.assertEquals;

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

  @Test
  void streamsOverFourThousandIncomingReferencesPreservesEncodedOrderAndCachesSnapshots() {
    // 5,005 incoming references (> 4,096 FlatProgramAPI cap), including negative operandIndex (-1),
    // multi-digit operandIndex (10), and Address.EXT_FROM_ADDRESS!
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

    // Verify exact ReferenceCursorKey.encoded sort order across the entire sweep!
    List<String> actualKeys =
        warmSweep.stream()
            .map(
                r ->
                    JsonUtil.toJson(
                        List.of(r.from(), r.to(), r.type(), r.operandIndex())))
            .toList();
    List<String> sortedKeys = new ArrayList<>(actualKeys);
    Collections.sort(sortedKeys);
    assertEquals(sortedKeys, actualKeys, "must preserve exact ReferenceCursorKey.encoded order");

    // Verify identical sweep when background analysis is running (stateless bounded selection).
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
      // Special operand indices and EXT_FROM_ADDRESS to verify exact encoded sort order & lookup.
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
                            exactLookup.get(lookupKey((Address) args[0], (Address) args[1], (int) args[2]));
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
