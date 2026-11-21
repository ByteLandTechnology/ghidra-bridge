package app.byteland.ghidra.adapter.ghidra;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.CompilerSpecDescription;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageDescription;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class DynamicProgramSwitchingTest {

  private static Program fakeProgram(String name, String md5, AtomicInteger txCount) {
    ghidra.program.model.address.AddressSpace ramSpace =
        (ghidra.program.model.address.AddressSpace)
            Proxy.newProxyInstance(
                ghidra.program.model.address.AddressSpace.class.getClassLoader(),
                new Class<?>[] {ghidra.program.model.address.AddressSpace.class},
                (proxy, method, args) -> "getName".equals(method.getName()) ? "ram" : null);
    Address minAddr =
        (Address)
            Proxy.newProxyInstance(
                Address.class.getClassLoader(),
                new Class<?>[] {Address.class},
                (proxy, method, args) ->
                    switch (method.getName()) {
                      case "toString" -> "00400000";
                      case "getAddressSpace" -> ramSpace;
                      default -> null;
                    });
    Address maxAddr =
        (Address)
            Proxy.newProxyInstance(
                Address.class.getClassLoader(),
                new Class<?>[] {Address.class},
                (proxy, method, args) ->
                    switch (method.getName()) {
                      case "toString" -> "00401000";
                      case "getAddressSpace" -> ramSpace;
                      default -> null;
                    });
    Address imageBase =
        (Address)
            Proxy.newProxyInstance(
                Address.class.getClassLoader(),
                new Class<?>[] {Address.class},
                (proxy, method, args) ->
                    switch (method.getName()) {
                      case "toString" -> "00400000";
                      case "getAddressSpace" -> ramSpace;
                      default -> null;
                    });
    Memory memory =
        (Memory)
            Proxy.newProxyInstance(
                Memory.class.getClassLoader(),
                new Class<?>[] {Memory.class},
                (proxy, method, args) -> {
                  return switch (method.getName()) {
                    case "getMinAddress" -> minAddr;
                    case "getMaxAddress" -> maxAddr;
                    default -> null;
                  };
                });
    LanguageDescription langDesc =
        (LanguageDescription)
            Proxy.newProxyInstance(
                LanguageDescription.class.getClassLoader(),
                new Class<?>[] {LanguageDescription.class},
                (proxy, method, args) ->
                    switch (method.getName()) {
                      case "getLanguageID" -> new LanguageID("x86:LE:64:default");
                      case "getProcessor" -> Processor.findOrPossiblyCreateProcessor("x86");
                      case "getSize" -> 64;
                      default -> null;
                    });
    Language language =
        (Language)
            Proxy.newProxyInstance(
                Language.class.getClassLoader(),
                new Class<?>[] {Language.class},
                (proxy, method, args) ->
                    switch (method.getName()) {
                      case "getLanguageDescription" -> langDesc;
                      case "isBigEndian" -> false;
                      default -> null;
                    });
    CompilerSpecDescription compilerDesc =
        (CompilerSpecDescription)
            Proxy.newProxyInstance(
                CompilerSpecDescription.class.getClassLoader(),
                new Class<?>[] {CompilerSpecDescription.class},
                (proxy, method, args) ->
                    "getCompilerSpecName".equals(method.getName()) ? "gcc" : null);
    CompilerSpec compilerSpec =
        (CompilerSpec)
            Proxy.newProxyInstance(
                CompilerSpec.class.getClassLoader(),
                new Class<?>[] {CompilerSpec.class},
                (proxy, method, args) ->
                    switch (method.getName()) {
                      case "getCompilerSpecDescription" -> compilerDesc;
                      case "getCompilerSpecID" ->
                          new ghidra.program.model.lang.CompilerSpecID("gcc");
                      default -> null;
                    });
    ghidra.program.model.listing.FunctionManager functionManager =
        (ghidra.program.model.listing.FunctionManager)
            Proxy.newProxyInstance(
                ghidra.program.model.listing.FunctionManager.class.getClassLoader(),
                new Class<?>[] {ghidra.program.model.listing.FunctionManager.class},
                (proxy, method, args) ->
                    "getFunctionCount".equals(method.getName()) ? 3 : null);
    ghidra.program.model.symbol.SymbolTable symbolTable =
        (ghidra.program.model.symbol.SymbolTable)
            Proxy.newProxyInstance(
                ghidra.program.model.symbol.SymbolTable.class.getClassLoader(),
                new Class<?>[] {ghidra.program.model.symbol.SymbolTable.class},
                (proxy, method, args) ->
                    "getNumSymbols".equals(method.getName()) ? 12 : null);
    AddressFactory addressFactory =
        (AddressFactory)
            Proxy.newProxyInstance(
                AddressFactory.class.getClassLoader(),
                new Class<?>[] {AddressFactory.class},
                (proxy, method, args) ->
                    "getAddressSpaces".equals(method.getName())
                        ? new ghidra.program.model.address.AddressSpace[0]
                        : null);

    return (Program)
        Proxy.newProxyInstance(
            Program.class.getClassLoader(),
            new Class<?>[] {Program.class},
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "getName" -> name;
                  case "getExecutablePath" -> "/tmp/" + name;
                  case "getExecutableFormat" -> "ELF";
                  case "getExecutableMD5" -> md5;
                  case "getExecutableSHA256" -> "0".repeat(64);
                  case "getImageBase" -> imageBase;
                  case "getMinAddress" -> minAddr;
                  case "getMaxAddress" -> maxAddr;
                  case "getMemory" -> memory;
                  case "getLanguage" -> language;
                  case "getLanguageID" -> new LanguageID("x86:LE:64:default");
                  case "getCompilerSpec" -> compilerSpec;
                  case "getFunctionManager" -> functionManager;
                  case "getSymbolTable" -> symbolTable;
                  case "getAddressFactory" -> addressFactory;
                  case "startTransaction" -> txCount.incrementAndGet();
                  case "endTransaction" -> true;
                  case "equals" -> proxy == args[0];
                  case "hashCode" -> System.identityHashCode(proxy);
                  case "toString" -> "FakeProgram[" + name + "]";
                  default -> null;
                });
  }

  @Test
  void switchesTargetProgramDynamicallyAndRunsCloseCallbacks() {
    AtomicInteger txAlpha = new AtomicInteger();
    AtomicInteger txBeta = new AtomicInteger();
    Program alpha = fakeProgram("alpha.elf", "a".repeat(32), txAlpha);
    Program beta = fakeProgram("beta.elf", "b".repeat(32), txBeta);

    AtomicReference<Program> active = new AtomicReference<>(alpha);
    GhidraSession session = new GhidraSession(active::get);
    List<Program> closedPrograms = new ArrayList<>();
    session.onProgramClosed(closedPrograms::add);

    try (var services = GhidraServiceFactory.create(session, "gui-test")) {
      assertEquals("alpha.elf", services.currentProgramName());
      assertEquals("alpha.elf", services.programService().getProgram().name());
      session.withTransaction(() -> "mutate-alpha");
      assertEquals(1, txAlpha.get());
      assertEquals(0, txBeta.get());

      // Switch the active tab to beta.elf.
      active.set(beta);
      assertEquals("beta.elf", services.currentProgramName());
      assertEquals("beta.elf", services.programService().getProgram().name());
      session.withTransaction(() -> "mutate-beta");
      assertEquals(1, txAlpha.get());
      assertEquals(1, txBeta.get());

      // Notify that alpha.elf closed.
      session.notifyProgramClosed(alpha);
      assertEquals(1, closedPrograms.size());
      assertSame(alpha, closedPrograms.get(0));

      // Clear the active program and verify fallback name and clean error.
      active.set(null);
      assertEquals("gui-test", services.currentProgramName());
      assertThrows(
          IllegalStateException.class, () -> services.programService().getProgram());
    }
  }
}
