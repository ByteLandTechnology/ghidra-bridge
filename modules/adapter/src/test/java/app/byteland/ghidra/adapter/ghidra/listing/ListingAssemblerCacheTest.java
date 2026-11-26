package app.byteland.ghidra.adapter.ghidra.listing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.AssemblyError;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import java.lang.reflect.Proxy;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class ListingAssemblerCacheTest {
  @Test
  void cachesAssemblerPerProgramInstance() {
    AtomicInteger creations = new AtomicInteger();
    ListingAssemblerCache cache =
        new ListingAssemblerCache(
            program -> {
              creations.incrementAndGet();
              return stubAssembler();
            });

    Program firstProgram = stubProgram("x86:LE:64:default");
    Program secondProgram = stubProgram("AARCH64:LE:64:v8A");

    Assembler first = cache.get(firstProgram);
    Assembler cachedFirst = cache.get(firstProgram);
    Assembler second = cache.get(secondProgram);

    assertSame(first, cachedFirst);
    assertEquals(2, creations.get());
    assertTrue(first != second);

    cache.releaseProgram(firstProgram);
    cache.releaseProgram(null);
    Assembler recreatedFirst = cache.get(firstProgram);
    assertEquals(3, creations.get());
    assertTrue(first != recreatedFirst);
  }

  @Test
  void translatesUnsupportedLanguageToIllegalArgumentException() {
    ListingAssemblerCache cache =
        new ListingAssemblerCache(
            program -> {
              throw new UnsupportedOperationException("no Sleigh grammar");
            });

    Program unsupported = stubProgram("DATA:LE:64:default");
    IllegalArgumentException error =
        assertThrows(IllegalArgumentException.class, () -> cache.get(unsupported));
    assertTrue(error.getMessage().contains("does not support Sleigh assembly"));
  }

  @Test
  void translatesAssemblyErrorToIllegalArgumentException() {
    AtomicInteger attempts = new AtomicInteger();
    ListingAssemblerCache cache =
        new ListingAssemblerCache(
            program -> {
              if (attempts.incrementAndGet() == 1) {
                throw new AssemblyError("corrupt Sleigh specification");
              }
              throw new AssemblyError("   ");
            });

    Program broken = stubProgram("x86:LE:64:default");
    IllegalArgumentException firstError =
        assertThrows(IllegalArgumentException.class, () -> cache.get(broken));
    assertEquals(
        "unable to initialize Sleigh assembler: corrupt Sleigh specification",
        firstError.getMessage());
    assertInstanceOf(AssemblyError.class, firstError.getCause());

    IllegalArgumentException blankDetailError =
        assertThrows(IllegalArgumentException.class, () -> cache.get(broken));
    assertEquals(
        "unable to initialize Sleigh assembler: x86:LE:64:default",
        blankDetailError.getMessage());
    assertInstanceOf(AssemblyError.class, blankDetailError.getCause());
    assertEquals(2, attempts.get());
  }

  private static Program stubProgram(String languageId) {
    return (Program)
        Proxy.newProxyInstance(
            Program.class.getClassLoader(),
            new Class<?>[] {Program.class},
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "equals" -> proxy == args[0];
                  case "hashCode" -> System.identityHashCode(proxy);
                  case "toString" -> "Program[" + languageId + "]";
                  case "getLanguageID" -> new LanguageID(languageId);
                  default -> throw new AssertionError(method.getName());
                });
  }

  private static Assembler stubAssembler() {
    return (Assembler)
        Proxy.newProxyInstance(
            Assembler.class.getClassLoader(),
            new Class<?>[] {Assembler.class},
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "equals" -> proxy == args[0];
                  case "hashCode" -> System.identityHashCode(proxy);
                  case "toString" -> "AssemblerStub";
                  default -> throw new AssertionError(method.getName());
                });
  }
}
