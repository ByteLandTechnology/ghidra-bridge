package app.byteland.ghidra.adapter.ghidra.reference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.listing.FlowOverrideScope;
import app.byteland.ghidra.service.reference.ReferenceResource;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.DefaultAddressFactory;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
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
    assertEquals(List.of(-1, 10), page1.items().stream().map(ReferenceResource::operandIndex).toList());
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
    assertEquals(List.of(2, 0), page2.items().stream().map(ReferenceResource::operandIndex).toList());
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

  @Test
  void populatesFromAndToFunctionSummariesForWinningReferencesOnly() {
    Address callerAddr = RAM.getAddress(0x00401010L);
    Address skippedCallerAddr = RAM.getAddress(0x00403010L);
    Address callerEntry = RAM.getAddress(0x00401000L);
    Address calleeEntry = RAM.getAddress(0x00405000L);
    AtomicInteger functionLookups = new AtomicInteger();
    AtomicInteger described = new AtomicInteger();

    Function callerFn = stubFunction(callerEntry, "caller_fn", null);
    Function calleeFn = stubFunction(calleeEntry, "callee_fn", null);
    FunctionManager fnManager =
        (FunctionManager)
            Proxy.newProxyInstance(
                FunctionManager.class.getClassLoader(),
                new Class<?>[] {FunctionManager.class},
                (proxy, method, args) -> {
                  if ("getFunctionContaining".equals(method.getName())) {
                    functionLookups.incrementAndGet();
                    Address addr = (Address) args[0];
                    if (callerAddr.equals(addr)) return callerFn;
                    if (calleeEntry.equals(addr)) return calleeFn;
                    return null;
                  }
                  throw new AssertionError(method.getName());
                });

    List<Reference> incoming =
        List.of(
            mockReference(
                skippedCallerAddr, calleeEntry, RefType.UNCONDITIONAL_CALL, 0, true, described),
            mockReference(callerAddr, calleeEntry, RefType.UNCONDITIONAL_CALL, 0, true, described));

    ReferenceListQueries queries =
        new ReferenceListQueries(
            sessionWithReferences(incoming, new Reference[0], new AtomicInteger(), fnManager));

    Page<ReferenceResource> page =
        queries.listReferences(null, "ram:00405000", null, "to", 1, null);
    assertEquals(1, page.items().size());
    assertEquals(1, described.get());
    assertEquals(2, functionLookups.get());
    assertEquals("caller_fn", page.items().getFirst().fromFunction().name());
    assertEquals("ram:00401000", page.items().getFirst().fromFunction().entry());
    assertEquals("callee_fn", page.items().getFirst().toFunction().name());
    assertEquals("ram:00405000", page.items().getFirst().toFunction().entry());
  }

  @Test
  void paginatesFunctionScopedReferencesWithCompositeCursorAndFunctionSummaries() {
    Address fnEntry = RAM.getAddress(0x00401000L);
    Address site1 = RAM.getAddress(0x00401004L);
    Address site2 = RAM.getAddress(0x00401010L);
    Address target1 = RAM.getAddress(0x00402000L);
    Address target2 = RAM.getAddress(0x00403000L);
    AddressSet body = new AddressSet(fnEntry, RAM.getAddress(0x00401020L));
    AtomicInteger described = new AtomicInteger();

    Function callerFn = stubFunction(fnEntry, "caller_fn", body);
    Function callee1 = stubFunction(target1, "callee_one", null);
    Function callee2 = stubFunction(target2, "callee_two", null);

    Reference ref1 = mockReference(site1, target1, RefType.UNCONDITIONAL_CALL, 0, true, described);
    Reference ref2 = mockReference(site2, target2, RefType.UNCONDITIONAL_CALL, 0, true, described);

    AddressFactory factory = new DefaultAddressFactory(new AddressSpace[] {RAM});
    Listing listing =
        (Listing)
            Proxy.newProxyInstance(
                Listing.class.getClassLoader(),
                new Class<?>[] {Listing.class},
                (proxy, method, args) -> {
                  if ("getFunctionAt".equals(method.getName())) {
                    return fnEntry.equals(args[0]) ? callerFn : null;
                  }
                  throw new AssertionError(method.getName());
                });
    FunctionManager fnManager =
        (FunctionManager)
            Proxy.newProxyInstance(
                FunctionManager.class.getClassLoader(),
                new Class<?>[] {FunctionManager.class},
                (proxy, method, args) -> {
                  if ("getFunctionContaining".equals(method.getName())) {
                    Address addr = (Address) args[0];
                    if (body.contains(addr)) return callerFn;
                    if (target1.equals(addr)) return callee1;
                    if (target2.equals(addr)) return callee2;
                    return null;
                  }
                  throw new AssertionError(method.getName());
                });
    ReferenceManager refManager =
        (ReferenceManager)
            Proxy.newProxyInstance(
                ReferenceManager.class.getClassLoader(),
                new Class<?>[] {ReferenceManager.class},
                (proxy, method, args) ->
                    switch (method.getName()) {
                      case "getReferenceSourceIterator" -> {
                        AddressSet set = (AddressSet) args[0];
                        List<Address> addrs = new ArrayList<>();
                        if (set.contains(site1)) addrs.add(site1);
                        if (set.contains(site2)) addrs.add(site2);
                        Iterator<Address> it = addrs.iterator();
                        yield (AddressIterator)
                            Proxy.newProxyInstance(
                                AddressIterator.class.getClassLoader(),
                                new Class<?>[] {AddressIterator.class},
                                (ip, im, ia) ->
                                    switch (im.getName()) {
                                      case "hasNext" -> it.hasNext();
                                      case "next" -> it.next();
                                      case "iterator" -> (AddressIterator) ip;
                                      default -> throw new AssertionError(im.getName());
                                    });
                      }
                      case "getReferencesFrom" -> {
                        Address addr = (Address) args[0];
                        if (site1.equals(addr)) yield new Reference[] {ref1};
                        if (site2.equals(addr)) yield new Reference[] {ref2};
                        yield new Reference[0];
                      }
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
                      case "getListing" -> listing;
                      case "getFunctionManager" -> fnManager;
                      case "getReferenceManager" -> refManager;
                      default -> throw new AssertionError(method.getName());
                    });

    ReferenceListQueries queries = new ReferenceListQueries(new GhidraSession(new TestScript(program)));
    AddressScanOptions defaultScan =
        new AddressScanOptions(null, null, AddressScanOptions.DEFAULT_TIMEOUT_MS);
    FlowOverrideScope scope = new FlowOverrideScope.FunctionScope("ram:00401000");

    Page<ReferenceResource> page1 =
        queries.listReferences(null, null, null, "from", scope, defaultScan, 1, null);
    assertEquals(1, page1.items().size());
    assertEquals("ram:00401004", page1.items().getFirst().from());
    assertEquals("caller_fn", page1.items().getFirst().fromFunction().name());
    assertEquals("callee_one", page1.items().getFirst().toFunction().name());

    Page<ReferenceResource> page2 =
        queries.listReferences(
            null, null, null, "from", scope, defaultScan, 2, page1.nextCursor());
    assertEquals(1, page2.items().size());
    assertEquals("ram:00401010", page2.items().getFirst().from());
    assertEquals("callee_two", page2.items().getFirst().toFunction().name());
    assertNull(page2.nextCursor());
  }

  private static Function stubFunction(Address entry, String name, AddressSet body) {
    return (Function)
        Proxy.newProxyInstance(
            Function.class.getClassLoader(),
            new Class<?>[] {Function.class},
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "getEntryPoint" -> entry;
                  case "getName" -> name;
                  case "getBody" -> body;
                  default -> throw new AssertionError(method.getName());
                });
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
    return sessionWithReferences(incoming, outgoing, incomingStreams, null);
  }

  private static GhidraSession sessionWithReferences(
      List<Reference> incoming,
      Reference[] outgoing,
      AtomicInteger incomingStreams,
      FunctionManager functionManager) {
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
                      case "getFunctionManager" -> functionManager;
                      default -> throw new AssertionError(method.getName());
                    });
    return new GhidraSession(new TestScript(program));
  }
}
