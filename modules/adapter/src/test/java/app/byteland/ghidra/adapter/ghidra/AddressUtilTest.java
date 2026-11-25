package app.byteland.ghidra.adapter.ghidra;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.DefaultAddressFactory;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.address.SegmentedAddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.lang.reflect.Proxy;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class AddressUtilTest {

  private static final class TestScript extends GhidraScript {
    private TestScript(Program program) {
      set(program, TaskMonitor.DUMMY);
    }

    @Override
    protected void run() {}
  }

  private static final class PoisonReadScript extends GhidraScript {
    private final Program exposedProgram;

    private PoisonReadScript(Program exposedProgram) {
      this.exposedProgram = exposedProgram;
      this.monitor =
          (TaskMonitor)
              Proxy.newProxyInstance(
                  TaskMonitor.class.getClassLoader(),
                  new Class<?>[] {TaskMonitor.class},
                  (proxy, method, args) -> {
                    throw new AssertionError("read path touched monitor: " + method.getName());
                  });
    }

    @Override
    protected void run() {}

    @Override
    public Program getCurrentProgram() {
      return exposedProgram;
    }
  }

  @Test
  void parseAddressResolvesCanonicalSpaceHexWithoutAddressEvaluator() {
    GenericAddressSpace ram = new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 0);
    GenericAddressSpace register =
        new GenericAddressSpace("register", 64, AddressSpace.TYPE_REGISTER, 1);
    AddressFactory factory = new DefaultAddressFactory(new AddressSpace[] {ram, register});
    Program strictProgram =
        (Program)
            Proxy.newProxyInstance(
                Program.class.getClassLoader(),
                new Class<?>[] {Program.class},
                (proxy, method, args) -> {
                  if ("getAddressFactory".equals(method.getName())) {
                    return factory;
                  }
                  throw new AssertionError("unexpected evaluator call: " + method.getName());
                });
    GhidraScript script = new TestScript(strictProgram);
    GhidraSession poisonSession = new GhidraSession(new PoisonReadScript(strictProgram));

    assertEquals(
        ram.getAddress(0x00401000L), AddressUtil.parseAddress(strictProgram, "ram:00401000"));
    assertEquals(ram.getAddress(0x00401000L), AddressUtil.parseAddress(script, "ram:00401000"));
    assertEquals(ram.getAddress(0x004010abL), AddressUtil.parseAddress(script, "  ram:0x4010AB "));
    assertEquals(register.getAddress(0x18L), poisonSession.parseAddress("register:0018"));
  }

  @Test
  void parseAddressFallsBackForBareOffsetsSegmentedSpacesExpressionsAndInvalidInput() {
    try (GhidraTestSupport.ProgramHolder holder =
        GhidraTestSupport.createX64Program("addr-fast-path")) {
      GhidraSession session = new GhidraSession(new PoisonReadScript(holder.program()));
      AddressSpace ram = holder.program().getAddressFactory().getDefaultAddressSpace();

      assertEquals(ram.getAddress(0x00402000L), session.parseAddress("00402000"));
      assertEquals(ram.getAddress(0x00402000L), session.parseAddress("0x402000"));
      assertEquals(ram.getAddress(0x00401010L), session.parseAddress("0x401000 + 0x10"));

      assertThrows(
          IllegalArgumentException.class,
          () -> AddressUtil.parseAddress((Program) null, "ram:0"));
      assertThrows(
          IllegalArgumentException.class,
          () -> AddressUtil.parseAddress((GhidraScript) null, "ram:0"));
      assertThrows(IllegalArgumentException.class, () -> session.parseAddress(" "));
      assertThrows(IllegalArgumentException.class, () -> session.parseAddress("unknown:zzzz"));
    }

    // Segmented address space bypasses the single-offset canonical fast-path.
    SegmentedAddressSpace segmented = new SegmentedAddressSpace("seg", 0);
    AddressFactory segmentedFactory = new DefaultAddressFactory(new AddressSpace[] {segmented});
    AtomicInteger factoryCalls = new AtomicInteger();
    Program segmentedProgram =
        (Program)
            Proxy.newProxyInstance(
                Program.class.getClassLoader(),
                new Class<?>[] {Program.class},
                (proxy, method, args) ->
                    switch (method.getName()) {
                      case "getAddressFactory" -> {
                        factoryCalls.incrementAndGet();
                        yield segmentedFactory;
                      }
                      case "getSymbolTable", "getEquateTable", "getMemory" -> null;
                      case "parseAddress" -> new Address[0];
                      default -> throw new AssertionError(method.getName());
                    });
    GhidraScript segmentedScript = new TestScript(segmentedProgram);
    assertEquals(
        segmented.getAddress(0x1000, 0x0020),
        AddressUtil.parseAddress(segmentedScript, "seg:1000:0020"));
    assertTrue(factoryCalls.get() > 1);

    factoryCalls.set(0);
    assertEquals(
        segmented.getAddress(0x0000, 0x0020),
        AddressUtil.parseAddress(segmentedScript, "seg:0020"));
    assertEquals(2, factoryCalls.get());
  }
}
