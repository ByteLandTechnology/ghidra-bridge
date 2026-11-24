package app.byteland.ghidra.adapter.ghidra.listing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import ghidra.app.plugin.assembler.Assembler;
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
