package app.byteland.ghidra.adapter.ghidra.function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.function.FunctionCallResource;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalReference;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import java.lang.reflect.Proxy;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class FunctionRelationEdgeCasesTest {
  private static final GenericAddressSpace RAM =
      new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 0);

  @Test
  void resolvesExternalAndTailJumpCallSitesAndRejectsMalformedCompositeCursors() {
    Function externalCallee = relatedFunction(0x00501000L, "ext_printf", "libc");
    Function tailCallee = relatedFunction(0x00502000L, "tail_helper", "Global");
    Address selfEntry = RAM.getAddress(0x00400000L);
    Address selfLoopSite = RAM.getAddress(0x00400004L);
    Address externalSite = RAM.getAddress(0x00400008L);
    Address tailSite = RAM.getAddress(0x00400010L);
    AddressSet body = new AddressSet(selfEntry, RAM.getAddress(0x00400020L));

    ExternalLocation extLoc =
        (ExternalLocation)
            Proxy.newProxyInstance(
                ExternalLocation.class.getClassLoader(),
                new Class<?>[] {ExternalLocation.class},
                (proxy, method, args) -> {
                  if ("getFunction".equals(method.getName())) return externalCallee;
                  throw new AssertionError(method.getName());
                });
    Reference externalRef =
        (Reference)
            Proxy.newProxyInstance(
                ExternalReference.class.getClassLoader(),
                new Class<?>[] {ExternalReference.class},
                (proxy, method, args) ->
                    switch (method.getName()) {
                      case "getFromAddress" -> externalSite;
                      case "getToAddress" -> null;
                      case "getReferenceType" -> RefType.UNCONDITIONAL_CALL;
                      case "getExternalLocation" -> extLoc;
                      default -> throw new AssertionError(method.getName());
                    });
    Reference tailJumpRef =
        callReference(tailSite, tailCallee.getEntryPoint(), RefType.UNCONDITIONAL_JUMP);

    Function[] selfHolder = new Function[1];
    Reference selfJumpRef = callReference(selfLoopSite, selfEntry, RefType.UNCONDITIONAL_JUMP);

    ReferenceManager refManager =
        (ReferenceManager)
            Proxy.newProxyInstance(
                ReferenceManager.class.getClassLoader(),
                new Class<?>[] {ReferenceManager.class},
                (proxy, method, args) ->
                    switch (method.getName()) {
                      case "getReferenceSourceIterator" ->
                          addressIterator(List.of(selfLoopSite, externalSite, tailSite).iterator());
                      case "getReferencesFrom" -> {
                        Address from = (Address) args[0];
                        if (selfLoopSite.equals(from)) yield new Reference[] {selfJumpRef};
                        if (externalSite.equals(from)) yield new Reference[] {externalRef};
                        if (tailSite.equals(from)) yield new Reference[] {tailJumpRef};
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
                    if (tailCallee.getEntryPoint().equals(addr)) return tailCallee;
                    if (selfEntry.equals(addr)) return selfHolder[0];
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
    Set<Function> calledSet = new LinkedHashSet<>(List.of(tailCallee));
    Function selfFn =
        (Function)
            Proxy.newProxyInstance(
                Function.class.getClassLoader(),
                new Class<?>[] {Function.class},
                (proxy, method, args) ->
                    switch (method.getName()) {
                      case "getEntryPoint" -> selfEntry;
                      case "getProgram" -> program;
                      case "getBody" -> body;
                      case "getCalledFunctions" -> calledSet;
                      default -> throw new AssertionError(method.getName());
                    });
    selfHolder[0] = selfFn;

    FunctionRelationQueries queries = new FunctionRelationQueries(raw -> selfFn);
    Page<FunctionCallResource> callees = queries.getCallees("ram:00400000", 10, null);
    assertEquals(
        List.of(
            new FunctionCallResource(
                "ram:00501000",
                "ext_printf",
                "ram:00400008",
                FunctionCallResource.Direction.CALLEES,
                "libc",
                null),
            new FunctionCallResource(
                "ram:00502000",
                "tail_helper",
                "ram:00400010",
                FunctionCallResource.Direction.CALLEES,
                "Global",
                null)),
        callees.items());

    assertThrows(
        IllegalArgumentException.class,
        () -> queries.getCallees("ram:00400000", 10, "ram:00501000\0"));
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

  private static Function relatedFunction(long offset, String name, String namespaceName) {
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
                  case "getParentNamespace" -> namespace;
                  case "getProgram" -> null;
                  case "hashCode" -> System.identityHashCode(proxy);
                  case "equals" -> proxy == args[0];
                  default -> throw new AssertionError(method.getName());
                });
  }
}
