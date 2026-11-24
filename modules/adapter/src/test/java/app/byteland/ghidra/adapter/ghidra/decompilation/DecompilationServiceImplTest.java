package app.byteland.ghidra.adapter.ghidra.decompilation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.decompilation.DecompilationResource;
import ghidra.app.decompiler.ClangBreak;
import ghidra.app.decompiler.ClangSyntaxToken;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.app.decompiler.PrettyPrinter;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.DefaultAddressFactory;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.lang.reflect.Proxy;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.IntSupplier;
import org.junit.jupiter.api.Test;

class DecompilationServiceImplTest {
  @Test
  void flushesCacheOnlyWhenProgramModificationNumberChanges() {
    AtomicLong modificationNumber = new AtomicLong(10L);
    Fixture fixture = createFixture(modificationNumber);
    FakeDecompiler decompiler = new FakeDecompiler(fixture.markup, true, null, () -> 0);

    try (DecompilationServiceImpl service =
        new DecompilationServiceImpl(fixture.session, new LeasePool<>(1, () -> decompiler))) {
      service.decompileFunction("0x101000", DecompilationResource.Format.TEXT, 1_200, false);
      assertEquals(1, decompiler.flushCalls.get());

      // Repeated reads at the same modification number skip cache flushes.
      service.decompileFunction("0x101000", DecompilationResource.Format.TEXT, 1_200, false);
      service.decompileFunction("0x101000", DecompilationResource.Format.DOCUMENT, 1_200, true);
      assertEquals(1, decompiler.flushCalls.get());

      // An increment to the program modification number triggers a new flush once.
      modificationNumber.set(11L);
      service.decompileFunction("0x101000", DecompilationResource.Format.TEXT, 1_200, true);
      assertEquals(2, decompiler.flushCalls.get());

      service.decompileFunction("0x101000", DecompilationResource.Format.TOKENS, 1_200, true);
      assertEquals(2, decompiler.flushCalls.get());
    }
  }

  @Test
  void retriesCacheFlushOnNextLeaseWhenFlushThrowsOrFails() {
    AtomicLong modificationNumber = new AtomicLong(1L);
    Fixture fixture = createFixture(modificationNumber);
    AtomicInteger mode = new AtomicInteger(0);
    FakeDecompiler decompiler =
        new FakeDecompiler(
            fixture.markup,
            true,
            null,
            () -> {
              return switch (mode.get()) {
                case 1 -> throw new IllegalStateException("ipc broken");
                case 2 -> -1;
                default -> 0;
              };
            });

    try (DecompilationServiceImpl service =
        new DecompilationServiceImpl(fixture.session, new LeasePool<>(1, () -> decompiler))) {
      service.decompileFunction("0x101000", DecompilationResource.Format.TEXT, 1_000, false);
      assertEquals(1, decompiler.flushCalls.get());

      // Modification changes to 2, but flushCache throws after it clears cached modification 1.
      modificationNumber.set(2L);
      mode.set(1);
      assertThrows(
          IllegalStateException.class,
          () ->
              service.decompileFunction(
                  "0x101000", DecompilationResource.Format.TEXT, 1_000, false));
      assertEquals(2, decompiler.flushCalls.get());

      // Next lease at the same modification 2 retries flushCache; negative status keeps it
      // uncached.
      mode.set(2);
      service.decompileFunction("0x101000", DecompilationResource.Format.TEXT, 1_000, false);
      assertEquals(3, decompiler.flushCalls.get());

      // Once flushCache succeeds (>= 0), modification 2 is cached and subsequent reads skip flush.
      mode.set(0);
      service.decompileFunction("0x101000", DecompilationResource.Format.TEXT, 1_000, false);
      assertEquals(4, decompiler.flushCalls.get());

      service.decompileFunction("0x101000", DecompilationResource.Format.TEXT, 1_000, false);
      assertEquals(4, decompiler.flushCalls.get());
    }
  }

  @Test
  void unifiesTextAndDocumentOutputViaPrettyPrinterAndHandlesTimedOutFallback() {
    AtomicLong modificationNumber = new AtomicLong(42L);
    Fixture fixture = createFixture(modificationNumber);
    FakeDecompiler decompiler = new FakeDecompiler(fixture.markup, true, null, () -> 0);

    try (DecompilationServiceImpl service =
        new DecompilationServiceImpl(fixture.session, new LeasePool<>(1, () -> decompiler))) {
      DecompilationResource textRes =
          service.decompileFunction("0x101000", DecompilationResource.Format.TEXT, 1_200, true);
      DecompilationResource docRes =
          service.decompileFunction("0x101000", DecompilationResource.Format.DOCUMENT, 1_200, true);

      assertTrue(textRes.completed());
      assertEquals(docRes.c(), textRes.c());
      assertTrue(
          textRes
              .c()
              .contains(PrettyPrinter.INDENT_STRING + "return \"semi; {brace} /*comment*/\";\n"));
      assertNull(textRes.lines());
      assertEquals(Boolean.TRUE, textRes.commentsComplete());
      assertEquals(List.of(), textRes.warnings());
    }

    FakeDecompiler timedOut = new FakeDecompiler(null, false, "Decompile timed out", () -> 0);
    timedOut.fallbackFunction =
        new DecompiledFunction("const char *f(void);", "/* raw fallback */");
    try (DecompilationServiceImpl service =
        new DecompilationServiceImpl(fixture.session, new LeasePool<>(1, () -> timedOut))) {
      DecompilationResource res =
          service.decompileFunction("0x101000", DecompilationResource.Format.TEXT, 1_200, false);
      assertFalse(res.completed());
      assertEquals("/* raw fallback */", res.c());
      assertEquals(List.of("Decompile timed out"), res.warnings());
    }
  }

  private static Fixture createFixture(AtomicLong modificationNumber) {
    GenericAddressSpace ram = new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 0);
    AddressFactory addressFactory = new DefaultAddressFactory(new AddressSpace[] {ram});
    Address entry = ram.getAddress(0x101000L);
    CodeUnit unit =
        (CodeUnit)
            Proxy.newProxyInstance(
                CodeUnit.class.getClassLoader(),
                new Class<?>[] {CodeUnit.class},
                (proxy, method, args) ->
                    switch (method.getName()) {
                      case "getMinAddress" -> entry;
                      default -> throw new AssertionError(method.getName());
                    });
    AddressIterator emptyComments =
        (AddressIterator)
            Proxy.newProxyInstance(
                AddressIterator.class.getClassLoader(),
                new Class<?>[] {AddressIterator.class},
                (proxy, method, args) ->
                    switch (method.getName()) {
                      case "iterator" -> Collections.emptyIterator();
                      case "hasNext" -> false;
                      default -> throw new AssertionError(method.getName());
                    });
    Function[] functionHolder = new Function[1];
    Listing listing =
        (Listing)
            Proxy.newProxyInstance(
                Listing.class.getClassLoader(),
                new Class<?>[] {Listing.class},
                (proxy, method, args) ->
                    switch (method.getName()) {
                      case "getFunctionAt" -> entry.equals(args[0]) ? functionHolder[0] : null;
                      case "getCodeUnitContaining" -> unit;
                      case "getCommentAddressIterator" -> {
                        assertEquals(CommentType.REPEATABLE, args[0]);
                        yield emptyComments;
                      }
                      default -> throw new AssertionError(method.getName());
                    });
    Program program =
        (Program)
            Proxy.newProxyInstance(
                Program.class.getClassLoader(),
                new Class<?>[] {Program.class},
                (proxy, method, args) ->
                    switch (method.getName()) {
                      case "getModificationNumber" -> modificationNumber.get();
                      case "getAddressFactory" -> addressFactory;
                      case "getListing" -> listing;
                      default -> throw new AssertionError(method.getName());
                    });
    Function function =
        (Function)
            Proxy.newProxyInstance(
                Function.class.getClassLoader(),
                new Class<?>[] {Function.class},
                (proxy, method, args) ->
                    switch (method.getName()) {
                      case "getProgram" -> program;
                      case "getEntryPoint" -> entry;
                      case "getName" -> "literal_demo";
                      case "getBody" -> null;
                      default -> throw new AssertionError(method.getName());
                    });
    functionHolder[0] = function;
    GhidraScript script =
        new GhidraScript() {
          {
            set(program, TaskMonitor.DUMMY);
          }

          @Override
          protected void run() {}
        };

    ClangTokenGroup markup = new ClangTokenGroup(null);
    markup.AddTokenGroup(new ClangToken(markup, "const char *", ClangToken.TYPE_COLOR));
    markup.AddTokenGroup(new ClangToken(markup, "literal_demo", ClangToken.FUNCTION_COLOR));
    markup.AddTokenGroup(new ClangSyntaxToken(markup, "(void)"));
    markup.AddTokenGroup(new ClangBreak(markup, 0));
    markup.AddTokenGroup(new ClangSyntaxToken(markup, "{"));
    markup.AddTokenGroup(new ClangBreak(markup, 1));
    markup.AddTokenGroup(new ClangToken(markup, "return", ClangToken.KEYWORD_COLOR));
    markup.AddTokenGroup(new ClangSyntaxToken(markup, " "));
    markup.AddTokenGroup(
        new ClangToken(markup, "\"semi; {brace} /*comment*/\"", ClangToken.CONST_COLOR));
    markup.AddTokenGroup(new ClangSyntaxToken(markup, ";"));
    markup.AddTokenGroup(new ClangBreak(markup, 0));
    markup.AddTokenGroup(new ClangSyntaxToken(markup, "}"));

    return new Fixture(new GhidraSession(script), markup);
  }

  private record Fixture(GhidraSession session, ClangTokenGroup markup) {}

  private static final class FakeDecompiler extends DecompInterface {
    private final ClangTokenGroup markup;
    private final boolean completed;
    private final String errorMessage;
    private final IntSupplier flushAction;
    private final AtomicInteger flushCalls = new AtomicInteger();
    private DecompiledFunction fallbackFunction;

    private FakeDecompiler(
        ClangTokenGroup markup, boolean completed, String errorMessage, IntSupplier flushAction) {
      this.markup = markup;
      this.completed = completed;
      this.errorMessage = errorMessage;
      this.flushAction = flushAction;
    }

    @Override
    public synchronized boolean setOptions(DecompileOptions xmlOptions) {
      return true;
    }

    @Override
    public synchronized int flushCache() {
      flushCalls.incrementAndGet();
      return flushAction.getAsInt();
    }

    @Override
    public synchronized DecompileResults decompileFunction(
        Function func, int timeoutSecs, TaskMonitor monitor) {
      return new DecompileResults(func, null, null, null, errorMessage, null, null) {
        @Override
        public boolean decompileCompleted() {
          return completed;
        }

        @Override
        public ClangTokenGroup getCCodeMarkup() {
          return markup;
        }

        @Override
        public DecompiledFunction getDecompiledFunction() {
          return fallbackFunction;
        }
      };
    }
  }
}
