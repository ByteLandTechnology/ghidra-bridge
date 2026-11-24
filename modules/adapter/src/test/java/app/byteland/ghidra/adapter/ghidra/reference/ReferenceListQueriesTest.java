package app.byteland.ghidra.adapter.ghidra.reference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
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
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
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
        new ReferenceListQueries(
            sessionWithReferences(incoming, new Reference[0], new AtomicInteger()));

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
}
