package app.byteland.ghidra.adapter.ghidra;

import static org.junit.jupiter.api.Assertions.assertEquals;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.DefaultAddressFactory;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.lang.reflect.Proxy;
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

    AddressSpace ram = new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 0);
    AddressFactory factory = new DefaultAddressFactory(new AddressSpace[] {ram});
    Program program =
        (Program)
            Proxy.newProxyInstance(
                Program.class.getClassLoader(),
                new Class<?>[] {Program.class},
                (proxy, method, args) ->
                    switch (method.getName()) {
                      case "getAddressFactory" -> factory;
                      default ->
                          throw new AssertionError("unexpected evaluator call: " + method.getName());
                    });
    GhidraScript script = new StubScript(program);

    Address parsedExternal = AddressUtil.parseAddress(script, "EXTERNAL:00000001");
    assertEquals(external, parsedExternal);
    assertEquals("EXTERNAL:00000001", AddressUtil.canonicalAddress(parsedExternal));
    assertEquals(external, AddressUtil.parseAddress(script, "external:0x1"));

    Address parsedRam = AddressUtil.parseAddress(script, "ram:00101000");
    assertEquals("ram:00101000", AddressUtil.canonicalAddress(parsedRam));
  }
}
