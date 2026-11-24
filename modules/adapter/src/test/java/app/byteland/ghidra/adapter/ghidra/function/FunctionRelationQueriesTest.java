package app.byteland.ghidra.adapter.ghidra.function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.function.FunctionCallResource;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import java.lang.reflect.Proxy;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class FunctionRelationQueriesTest {
  private static final GenericAddressSpace RAM =
      new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 0);

  @Test
  void populatesCallSitesForCallersAndCalleesAndDeduplicatesSameSiteOperands() {
    Address callerAEntry = addr(0x401000);
    Address callerASiteOne = addr(0x401014);
    Address callerASiteTwo = addr(0x401028);
    Address callerBEntry = addr(0x402000);
    Address callerBSite = addr(0x402010);
    Address targetEntry = addr(0x403000);
    Address targetSiteOne = addr(0x403008);
    Address targetSiteTwo = addr(0x40301c);
    Address targetDataSite = addr(0x403024);
    Address calleeEntry = addr(0x404000);

    AddressSet targetBody = new AddressSet(targetEntry, addr(0x403040));

    List<Reference> incomingToTarget =
        List.of(
            ref(callerASiteTwo, targetEntry, RefType.UNCONDITIONAL_CALL),
            ref(callerASiteOne, targetEntry, RefType.UNCONDITIONAL_CALL),
            ref(callerASiteOne, targetEntry, RefType.COMPUTED_CALL),
            ref(addr(0x405000), targetEntry, RefType.DATA),
            ref(callerBSite, targetEntry, RefType.CONDITIONAL_CALL));

    Map<Address, Reference[]> outgoingFromTarget =
        Map.of(
            targetSiteOne,
            new Reference[] {
              ref(targetSiteOne, calleeEntry, RefType.UNCONDITIONAL_CALL),
              ref(targetSiteOne, calleeEntry, RefType.UNCONDITIONAL_CALL)
            },
            targetSiteTwo,
            new Reference[] {ref(targetSiteTwo, calleeEntry, RefType.UNCONDITIONAL_CALL)},
            targetDataSite,
            new Reference[] {ref(targetDataSite, calleeEntry, RefType.READ)});

    Program[] holder = new Program[1];
    Function callerA = mockFunction(holder, callerAEntry, "caller_a", "Global", new AddressSet());
    Function callerB = mockFunction(holder, callerBEntry, "caller_b", "App", new AddressSet());
    Function target = mockFunction(holder, targetEntry, "target", "Global", targetBody);
    Function callee = mockFunction(holder, calleeEntry, "callee", "Lib", new AddressSet());

    FunctionManager functionManager =
        proxy(
            FunctionManager.class,
            (method, args) -> {
              if ("getFunctionContaining".equals(method)) {
                Address address = (Address) args[0];
                if (address.equals(callerASiteOne) || address.equals(callerASiteTwo)) {
                  return callerA;
                }
                if (address.equals(callerBSite)) {
                  return callerB;
                }
                return null;
              }
              if ("getFunctionAt".equals(method)) {
                Address address = (Address) args[0];
                return address.equals(calleeEntry) ? callee : null;
              }
              return null;
            });

    ReferenceManager referenceManager =
        proxy(
            ReferenceManager.class,
            (method, args) -> {
              if ("getReferencesTo".equals(method)) {
                return referenceIterator(incomingToTarget);
              }
              if ("getReferenceSourceIterator".equals(method)) {
                return addressIterator(List.of(targetSiteOne, targetSiteTwo, targetDataSite));
              }
              if ("getReferencesFrom".equals(method)) {
                return outgoingFromTarget.getOrDefault((Address) args[0], new Reference[0]);
              }
              return null;
            });

    holder[0] =
        proxy(
            Program.class,
            (method, args) -> {
              if ("getReferenceManager".equals(method)) return referenceManager;
              if ("getFunctionManager".equals(method)) return functionManager;
              return null;
            });

    FunctionRelationQueries queries = new FunctionRelationQueries(ignored -> target);

    Page<FunctionCallResource> callersPageOne = queries.getCallers("0x403000", 2, null);
    assertEquals(2, callersPageOne.items().size());
    assertEquals("ram:00401000", callersPageOne.items().get(0).entry());
    assertEquals("ram:00401014", callersPageOne.items().get(0).callSite());
    assertEquals("ram:00401000", callersPageOne.items().get(1).entry());
    assertEquals("ram:00401028", callersPageOne.items().get(1).callSite());
    assertNotNull(callersPageOne.nextCursor());

    Page<FunctionCallResource> callersPageTwo =
        queries.getCallers("0x403000", 2, callersPageOne.nextCursor());
    assertEquals(1, callersPageTwo.items().size());
    assertEquals("ram:00402000", callersPageTwo.items().getFirst().entry());
    assertEquals("ram:00402010", callersPageTwo.items().getFirst().callSite());
    assertEquals("App", callersPageTwo.items().getFirst().namespace());
    assertNull(callersPageTwo.nextCursor());

    Page<FunctionCallResource> calleesPage = queries.getCallees("0x403000", 10, null);
    assertEquals(2, calleesPage.items().size());
    assertEquals("ram:00404000", calleesPage.items().get(0).entry());
    assertEquals("ram:00403008", calleesPage.items().get(0).callSite());
    assertEquals("ram:00404000", calleesPage.items().get(1).entry());
    assertEquals("ram:0040301c", calleesPage.items().get(1).callSite());
  }

  private static Address addr(long offset) {
    return RAM.getAddress(offset);
  }

  private static Function mockFunction(
      Program[] programHolder,
      Address entry,
      String name,
      String namespaceName,
      AddressSetView body) {
    Namespace namespace =
        proxy(Namespace.class, (method, args) -> "getName".equals(method) ? namespaceName : null);
    return proxy(
        Function.class,
        (method, args) ->
            switch (method) {
              case "getEntryPoint" -> entry;
              case "getName" -> name;
              case "getParentNamespace" -> namespace;
              case "getBody" -> body;
              case "getProgram" -> programHolder[0];
              default -> null;
            });
  }

  private static Reference ref(Address from, Address to, RefType type) {
    return proxy(
        Reference.class,
        (method, args) ->
            switch (method) {
              case "getFromAddress" -> from;
              case "getToAddress" -> to;
              case "getReferenceType" -> type;
              default -> null;
            });
  }

  private static ReferenceIterator referenceIterator(List<Reference> references) {
    Iterator<Reference> iterator = references.iterator();
    return proxy(
        ReferenceIterator.class,
        (method, args) ->
            switch (method) {
              case "hasNext" -> iterator.hasNext();
              case "next" -> iterator.next();
              case "iterator" -> iterator;
              default -> null;
            });
  }

  private static AddressIterator addressIterator(List<Address> addresses) {
    Iterator<Address> iterator = addresses.iterator();
    return proxy(
        AddressIterator.class,
        (method, args) ->
            switch (method) {
              case "hasNext" -> iterator.hasNext();
              case "next" -> iterator.next();
              case "iterator" -> iterator;
              default -> null;
            });
  }

  private interface Handler {
    Object invoke(String method, Object[] args);
  }

  private static <T> T proxy(Class<T> type, Handler handler) {
    return type.cast(
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (proxy, method, args) -> handler.invoke(method.getName(), args)));
  }
}
