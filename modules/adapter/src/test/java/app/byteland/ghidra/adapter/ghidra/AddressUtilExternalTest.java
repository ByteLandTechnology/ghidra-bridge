package app.byteland.ghidra.adapter.ghidra;

import static org.junit.jupiter.api.Assertions.assertEquals;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.DefaultAddressFactory;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.task.TaskMonitor;
import java.lang.reflect.Proxy;
import java.util.Collections;
import org.junit.jupiter.api.Test;

class AddressUtilExternalTest {
  private static final class StubScript extends GhidraScript {
    private StubScript(Program program) {
      set(program, TaskMonitor.DUMMY);
    }

    @Override
    protected void run() {}
  }

  @Test
  void formatsAndParsesExternalSpaceAddressesWithoutDuplicatePrefix() {
    Address external = AddressSpace.EXTERNAL_SPACE.getAddress(1);
    assertEquals("EXTERNAL:00000001", AddressUtil.canonicalAddress(external));
    assertEquals("0x00000001", AddressUtil.offset(external));

    AddressSpace ram = new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 0);
    AddressFactory factory = new DefaultAddressFactory(new AddressSpace[] {ram});
    Memory memory =
        (Memory)
            Proxy.newProxyInstance(
                Memory.class.getClassLoader(),
                new Class<?>[] {Memory.class},
                (proxy, method, args) -> null);
    SymbolTable symbols =
        (SymbolTable)
            Proxy.newProxyInstance(
                SymbolTable.class.getClassLoader(),
                new Class<?>[] {SymbolTable.class},
                (proxy, method, args) -> {
                  if (SymbolIterator.class.isAssignableFrom(method.getReturnType())) {
                    return SymbolIterator.EMPTY_ITERATOR;
                  }
                  if ("getLabelOrFunctionSymbols".equals(method.getName())
                      || "getGlobalSymbols".equals(method.getName())) {
                    return Collections.emptyList();
                  }
                  return null;
                });
    Program program =
        (Program)
            Proxy.newProxyInstance(
                Program.class.getClassLoader(),
                new Class<?>[] {Program.class},
                (proxy, method, args) ->
                    switch (method.getName()) {
                      case "getAddressFactory" -> factory;
                      case "getMemory" -> memory;
                      case "getSymbolTable" -> symbols;
                      default -> null;
                    });
    GhidraScript script = new StubScript(program);

    Address parsedExternal = AddressUtil.parseAddress(script, "EXTERNAL:00000001");
    assertEquals(external, parsedExternal);
    assertEquals("EXTERNAL:00000001", AddressUtil.canonicalAddress(parsedExternal));

    Address parsedRam = AddressUtil.parseAddress(script, "ram:00101000");
    assertEquals("ram:00101000", AddressUtil.canonicalAddress(parsedRam));
  }
}
