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
    assertEquals("ram:00402000\0-", page1.nextCursor());
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
}
