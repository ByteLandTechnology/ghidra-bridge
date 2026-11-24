package app.byteland.ghidra.adapter.ghidra.function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.function.FunctionCallResource;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Namespace;
import java.lang.reflect.Proxy;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class FunctionRelationQueriesTest {
  private static final GenericAddressSpace RAM =
      new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 0);

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
    assertEquals(FunctionCallResource.Direction.CALLEES, exactLimitCallees.items().getFirst().direction());
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

    ghidra.program.model.address.AddressSet body =
        new ghidra.program.model.address.AddressSet(
            RAM.getAddress(0x00400000L), RAM.getAddress(0x00400030L));
    List<Address> sourceAddrs = List.of(siteLate, siteEarly, siteB);

    ghidra.program.model.symbol.Reference refA2 =
        callReference(siteLate, helperA.getEntryPoint(), ghidra.program.model.symbol.RefType.UNCONDITIONAL_CALL);
    ghidra.program.model.symbol.Reference refA1 =
        callReference(siteEarly, helperA.getEntryPoint(), ghidra.program.model.symbol.RefType.UNCONDITIONAL_CALL);
    ghidra.program.model.symbol.Reference refDataIgnored =
        callReference(siteEarly, helperB.getEntryPoint(), ghidra.program.model.symbol.RefType.DATA);
    ghidra.program.model.symbol.Reference refB =
        callReference(siteB, helperB.getEntryPoint(), ghidra.program.model.symbol.RefType.COMPUTED_CALL);

    ghidra.program.model.symbol.ReferenceManager refManager =
        (ghidra.program.model.symbol.ReferenceManager)
            Proxy.newProxyInstance(
                ghidra.program.model.symbol.ReferenceManager.class.getClassLoader(),
                new Class<?>[] {ghidra.program.model.symbol.ReferenceManager.class},
                (proxy, method, args) ->
                    switch (method.getName()) {
                      case "getReferenceSourceIterator" -> addressIterator(sourceAddrs.iterator());
                      case "getReferencesFrom" -> {
                        Address from = (Address) args[0];
                        if (siteLate.equals(from)) {
                          yield new ghidra.program.model.symbol.Reference[] {refA2};
                        }
                        if (siteEarly.equals(from)) {
                          yield new ghidra.program.model.symbol.Reference[] {refA1, refDataIgnored};
                        }
                        if (siteB.equals(from)) {
                          yield new ghidra.program.model.symbol.Reference[] {refB};
                        }
                        yield new ghidra.program.model.symbol.Reference[0];
                      }
                      default -> throw new AssertionError(method.getName());
                    });
    ghidra.program.model.listing.FunctionManager fnManager =
        (ghidra.program.model.listing.FunctionManager)
            Proxy.newProxyInstance(
                ghidra.program.model.listing.FunctionManager.class.getClassLoader(),
                new Class<?>[] {ghidra.program.model.listing.FunctionManager.class},
                (proxy, method, args) -> {
                  if ("getFunctionAt".equals(method.getName())) {
                    Address addr = (Address) args[0];
                    if (helperA.getEntryPoint().equals(addr)) return helperA;
                    if (helperB.getEntryPoint().equals(addr)) return helperB;
                    return null;
                  }
                  throw new AssertionError(method.getName());
                });
    ghidra.program.model.listing.Program program =
        (ghidra.program.model.listing.Program)
            Proxy.newProxyInstance(
                ghidra.program.model.listing.Program.class.getClassLoader(),
                new Class<?>[] {ghidra.program.model.listing.Program.class},
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
    assertEquals(
        app.byteland.ghidra.adapter.ghidra.scan.CompositeCursor.key(
            "ram:00401000", "ram:00400020"),
        page1.nextCursor());
    assertEquals(2, namespaceLookups.get());

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
    assertEquals(4, namespaceLookups.get());
  }

  private static ghidra.program.model.address.AddressIterator addressIterator(
      java.util.Iterator<Address> iterator) {
    return (ghidra.program.model.address.AddressIterator)
        Proxy.newProxyInstance(
            ghidra.program.model.address.AddressIterator.class.getClassLoader(),
            new Class<?>[] {ghidra.program.model.address.AddressIterator.class},
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "hasNext" -> iterator.hasNext();
                  case "next" -> iterator.next();
                  case "iterator" -> (ghidra.program.model.address.AddressIterator) proxy;
                  default -> throw new AssertionError(method.getName());
                });
  }

  private static ghidra.program.model.symbol.Reference callReference(
      Address from, Address to, ghidra.program.model.symbol.RefType refType) {
    return (ghidra.program.model.symbol.Reference)
        Proxy.newProxyInstance(
            ghidra.program.model.symbol.Reference.class.getClassLoader(),
            new Class<?>[] {ghidra.program.model.symbol.Reference.class},
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "getFromAddress" -> from;
                  case "getToAddress" -> to;
                  case "getReferenceType" -> refType;
                  default -> throw new AssertionError(method.getName());
                });
  }

  private static Function rootFunction(Set<Function> callers, Set<Function> callees) {
    return (Function)
        Proxy.newProxyInstance(
            Function.class.getClassLoader(),
            new Class<?>[] {Function.class},
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "getProgram" -> null;
                  case "getCallingFunctions" -> callers;
                  case "getCalledFunctions" -> callees;
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
}
