package app.byteland.ghidra.adapter.ghidra.reference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.reference.ReferenceResource;
import app.byteland.ghidra.service.reference.ReferenceService;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.DefaultAddressFactory;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import org.junit.jupiter.api.Test;

class ReferenceListQueriesTest {
  private static final GenericAddressSpace RAM =
      new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 0);
  private static final GenericAddressSpace OTHER =
      new GenericAddressSpace("other", 64, AddressSpace.TYPE_OTHER, 1);

  @Test
  void scansReferencesAcrossFunctionEntryAndFromRangeWithDeterministicPagination() {
    Address fnEntry = addr(0x401000);
    Address branchOne = addr(0x40100c);
    Address branchTwo = addr(0x401018);
    Address outside = addr(0x402000);
    Address targetOne = addr(0x401030);
    Address targetTwo = addr(0x401040);

    AddressSet body = new AddressSet(fnEntry, addr(0x401050));
    Map<Address, Reference[]> outgoing =
        Map.of(
            branchOne,
            new Reference[] {ref(branchOne, targetOne, RefType.CONDITIONAL_JUMP, 0, true)},
            branchTwo,
            new Reference[] {ref(branchTwo, targetTwo, RefType.UNCONDITIONAL_JUMP, 0, true)},
            outside,
            new Reference[] {ref(outside, targetOne, RefType.UNCONDITIONAL_CALL, 0, true)});

    Function function =
        proxy(Function.class, (method, args) -> "getBody".equals(method) ? body : null);
    FunctionManager functionManager =
        proxy(
            FunctionManager.class,
            (method, args) -> {
              if ("getFunctionAt".equals(method)) {
                return fnEntry.equals(args[0]) ? function : null;
              }
              return null;
            });
    ReferenceManager referenceManager =
        proxy(
            ReferenceManager.class,
            (method, args) -> {
              if ("getReferenceSourceIterator".equals(method)) {
                AddressSetView range = (AddressSetView) args[0];
                List<Address> matches = new ArrayList<>();
                for (Address candidate : List.of(branchTwo, branchOne, outside)) {
                  if (range.contains(candidate)) {
                    matches.add(candidate);
                  }
                }
                return addressIterator(matches);
              }
              if ("getReferencesFrom".equals(method)) {
                return outgoing.getOrDefault((Address) args[0], new Reference[0]);
              }
              return null;
            });
    DefaultAddressFactory addressFactory =
        new DefaultAddressFactory(new AddressSpace[] {RAM, OTHER});
    RAM.setShowSpaceName(false);
    Program program =
        proxy(
            Program.class,
            (method, args) ->
                switch (method) {
                  case "getFunctionManager" -> functionManager;
                  case "getReferenceManager" -> referenceManager;
                  case "getAddressFactory" -> addressFactory;
                  default -> null;
                });

    GhidraScript script =
        new GhidraScript() {
          {
            this.currentProgram = program;
          }

          @Override
          protected void run() {}
        };

    ReferenceListQueries queries = new ReferenceListQueries(new GhidraSession(script));

    Page<ReferenceResource> pageOne =
        queries.listReferences(null, "0x401000", null, null, null, "from", 1, null);
    assertEquals(1, pageOne.items().size());
    assertEquals("ram:0040100c", pageOne.items().getFirst().from());
    assertEquals("CONDITIONAL_JUMP", pageOne.items().getFirst().type());
    assertNotNull(pageOne.nextCursor());

    Page<ReferenceResource> pageTwo =
        queries.listReferences(
            null, "0x401000", null, null, null, "from", 1, pageOne.nextCursor());
    assertEquals(1, pageTwo.items().size());
    assertEquals("ram:00401018", pageTwo.items().getFirst().from());
    assertEquals("UNCONDITIONAL_JUMP", pageTwo.items().getFirst().type());
    assertNull(pageTwo.nextCursor());

    Page<ReferenceResource> filteredRange =
        queries.listReferences(
            null,
            null,
            new ReferenceService.RangeFilter("0x401000", "0x402010"),
            null,
            "UNCONDITIONAL_CALL",
            "from",
            10,
            null);
    assertEquals(1, filteredRange.items().size());
    assertEquals("ram:00402000", filteredRange.items().getFirst().from());

    assertThrows(
        NoSuchElementException.class,
        () -> queries.listReferences(null, "0x409000", null, null, null, "from", 10, null));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            queries.listReferences(
                "0x401000", "0x401000", null, null, null, "from", 10, null));
    assertThrows(
        IllegalArgumentException.class,
        () -> queries.listReferences(null, "0x401000", null, "0x401030", null, "to", 10, null));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            queries.listReferences(
                null,
                null,
                new ReferenceService.RangeFilter("0x402000", "0x401000"),
                null,
                null,
                "from",
                10,
                null));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            queries.listReferences(
                null,
                null,
                new ReferenceService.RangeFilter("0x401000", "other:10"),
                null,
                null,
                "from",
                10,
                null));
  }

  private static Address addr(long offset) {
    return RAM.getAddress(offset);
  }

  private static Reference ref(
      Address from, Address to, RefType type, int operandIndex, boolean primary) {
    return proxy(
        Reference.class,
        (method, args) ->
            switch (method) {
              case "getFromAddress" -> from;
              case "getToAddress" -> to;
              case "getReferenceType" -> type;
              case "getOperandIndex" -> operandIndex;
              case "isPrimary" -> primary;
              case "getSource" -> SourceType.DEFAULT;
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
