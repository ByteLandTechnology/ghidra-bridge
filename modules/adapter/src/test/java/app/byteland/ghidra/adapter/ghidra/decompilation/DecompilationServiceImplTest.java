package app.byteland.ghidra.adapter.ghidra.decompilation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.IntSupplier;
import org.junit.jupiter.api.Test;

class DecompilationServiceImplTest {
  private static final AddressSpace RAM_SPACE =
      new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 0);
  private static final AddressFactory ADDRESS_FACTORY =
      new DefaultAddressFactory(new AddressSpace[] {RAM_SPACE}, RAM_SPACE);

  @Test
  void skipsColdFlushAndFlushesOnlyWhenProgramModificationNumberChanges() {
    AtomicLong modificationNumber = new AtomicLong(10L);
    Fixture fixture = createFixture(modificationNumber);
    fixture.addFunction(0x102000L, "helper_demo", fixture.program);
    FakeDecompiler decompiler = new FakeDecompiler(fixture.markup, true, null, () -> 0);

    try (DecompilationServiceImpl service = new DecompilationServiceImpl(
        fixture.session, new LeasePool<>(1, () -> decompiler))) {
      // Cold decompile on a new decompiler skips flushCache.
      DecompilationResource first =
          service.decompileFunction("0x101000", DecompilationResource.Format.TEXT, 1_200, false);
      assertEquals("literal_demo", first.name());
      assertEquals(0, decompiler.flushCalls.get());
      assertEquals(1, decompiler.decompileCalls.get());
      assertEquals(1, decompiler.setOptionsCalls.get());

      // Repeated reads across functions, formats, and comment modes skip cache flushes.
      service.decompileFunction("0x101000", DecompilationResource.Format.TEXT, 1_200, false);
      DecompilationResource secondFn =
          service.decompileFunction("0x102000", DecompilationResource.Format.TOKENS, 1_200, false);
      assertEquals("helper_demo", secondFn.name());
      assertEquals(1, decompiler.setOptionsCalls.get());
      service.decompileFunction("0x101000", DecompilationResource.Format.DOCUMENT, 1_200, true);
      assertEquals(0, decompiler.flushCalls.get());
      assertEquals(2, decompiler.setOptionsCalls.get());

      // An increment to the program modification number triggers a new flush once.
      modificationNumber.set(11L);
      service.decompileFunction("0x101000", DecompilationResource.Format.TEXT, 1_200, true);
      assertEquals(1, decompiler.flushCalls.get());
      assertEquals(1, decompiler.flushCallsBeforeLastDecompile);

      service.decompileFunction("0x101000", DecompilationResource.Format.TOKENS, 1_200, true);
      assertEquals(1, decompiler.flushCalls.get());
    }
  }

  @Test
  void flushesCacheWhenModificationNumberDecrementsOnRollbackOrUndo() {
    AtomicLong modificationNumber = new AtomicLong(50L);
    Fixture fixture = createFixture(modificationNumber);
    FakeDecompiler decompiler = new FakeDecompiler(fixture.markup, true, null, () -> 0);

    try (DecompilationServiceImpl service = new DecompilationServiceImpl(
        fixture.session, new LeasePool<>(1, () -> decompiler))) {
      service.decompileFunction("0x101000", DecompilationResource.Format.TEXT, 1_200, false);
      assertEquals(0, decompiler.flushCalls.get());

      // Uncommitted edit increments modificationNumber to 51 and flushes.
      modificationNumber.set(51L);
      service.decompileFunction("0x101000", DecompilationResource.Format.TEXT, 1_200, false);
      assertEquals(1, decompiler.flushCalls.get());

      // Transaction rollback or undo resets modificationNumber to 50 (< 51) and flushes.
      modificationNumber.set(50L);
      service.decompileFunction("0x101000", DecompilationResource.Format.TEXT, 1_200, false);
      assertEquals(2, decompiler.flushCalls.get());

      service.decompileFunction("0x101000", DecompilationResource.Format.TEXT, 1_200, false);
      assertEquals(2, decompiler.flushCalls.get());
    }
  }

  @Test
  void retriesCacheFlushOnNextLeaseWhenFlushThrowsOrFailsIncludingAfterRollback() {
    AtomicLong modificationNumber = new AtomicLong(1L);
    Fixture fixture = createFixture(modificationNumber);
    AtomicInteger mode = new AtomicInteger(0);
    FakeDecompiler decompiler = new FakeDecompiler(fixture.markup, true, null, () -> {
      return switch (mode.get()) {
        case 1 -> throw new IllegalStateException("ipc broken");
        case 2 -> -1;
        default -> 0;
      };
    });

    try (DecompilationServiceImpl service = new DecompilationServiceImpl(
        fixture.session, new LeasePool<>(1, () -> decompiler))) {
      service.decompileFunction("0x101000", DecompilationResource.Format.TEXT, 1_000, false);
      assertEquals(0, decompiler.flushCalls.get());
      assertEquals(1, decompiler.decompileCalls.get());

      // Modification changes to 2, and flushCache throws after it marks the cache state dirty.
      modificationNumber.set(2L);
      mode.set(1);
      assertThrows(
          IllegalStateException.class,
          () -> service.decompileFunction(
              "0x101000", DecompilationResource.Format.TEXT, 1_000, false));
      assertEquals(1, decompiler.flushCalls.get());
      assertEquals(1, decompiler.decompileCalls.get());

      // Next lease at modification 2 retries flushCache; negative status keeps it dirty.
      mode.set(2);
      service.decompileFunction("0x101000", DecompilationResource.Format.TEXT, 1_000, false);
      assertEquals(2, decompiler.flushCalls.get());

      // Even if modificationNumber resets to 1 (equal to the prior clean value), dirty forces retry.
      modificationNumber.set(1L);
      mode.set(0);
      service.decompileFunction("0x101000", DecompilationResource.Format.TEXT, 1_000, false);
      assertEquals(3, decompiler.flushCalls.get());

      // Once flushCache succeeds (>= 0), modification 1 is clean and subsequent reads skip flush.
      service.decompileFunction("0x101000", DecompilationResource.Format.TEXT, 1_000, false);
      assertEquals(3, decompiler.flushCalls.get());
    }
  }

  @Test
  void flushesCacheWhenProgramReferenceChangesOrProgramIsAbsent() {
    Fixture fixtureA = createFixture(new AtomicLong(7L));
    Fixture fixtureB = createFixture(new AtomicLong(7L));
    fixtureB.addFunction(0x101000L, "from_program_b", fixtureB.program);
    fixtureB.addFunction(0x103000L, "orphan_demo", null);

    FakeDecompiler decompiler = new FakeDecompiler(fixtureA.markup, true, null, () -> 0);
    decompiler.openedProgram = fixtureA.program;

    try (DecompilationServiceImpl service = new DecompilationServiceImpl(
        fixtureA.session, new LeasePool<>(1, () -> decompiler))) {
      DecompilationResource first =
          service.decompileFunction("0x101000", DecompilationResource.Format.TEXT, 1_200, false);
      assertEquals("literal_demo", first.name());
      assertEquals(0, decompiler.flushCalls.get());

      // Switch to a distinct Program instance that has the same modificationNumber (7L).
      fixtureA.script.switchProgram(fixtureB.program);
      DecompilationResource second =
          service.decompileFunction("0x101000", DecompilationResource.Format.TEXT, 1_200, false);
      assertEquals("from_program_b", second.name());
      assertEquals(1, decompiler.flushCalls.get());
      assertEquals(1, decompiler.flushCallsBeforeLastDecompile);

      service.decompileFunction("0x101000", DecompilationResource.Format.TEXT, 1_200, false);
      assertEquals(1, decompiler.flushCalls.get());

      // Absent Program flushes the cache and marks the decompiler dirty for the next Program.
      fixtureA.script.hideCurrentProgram = true;
      DecompilationResource orphan =
          service.decompileFunction("0x103000", DecompilationResource.Format.TEXT, 1_200, false);
      assertEquals("orphan_demo", orphan.name());
      assertEquals(2, decompiler.flushCalls.get());

      fixtureA.script.hideCurrentProgram = false;
      service.decompileFunction("0x101000", DecompilationResource.Format.TEXT, 1_200, false);
      assertEquals(3, decompiler.flushCalls.get());

      service.decompileFunction("0x101000", DecompilationResource.Format.TEXT, 1_200, false);
      assertEquals(3, decompiler.flushCalls.get());
    }

    // Cold lease whose DecompInterface opened a different Program must also flush.
    FakeDecompiler mismatchedCold = new FakeDecompiler(fixtureB.markup, true, null, () -> 0);
    mismatchedCold.openedProgram = fixtureA.program;
    try (DecompilationServiceImpl service = new DecompilationServiceImpl(
        fixtureB.session, new LeasePool<>(1, () -> mismatchedCold))) {
      service.decompileFunction("0x101000", DecompilationResource.Format.TEXT, 1_200, false);
      assertEquals(1, mismatchedCold.flushCalls.get());
    }
  }

  @Test
  void tracksCacheStateIndependentlyPerPooledDecompiler() {
    AtomicLong modificationNumber = new AtomicLong(10L);
    Fixture fixture = createFixture(modificationNumber);
    FakeDecompiler firstDecompiler = new FakeDecompiler(fixture.markup, true, null, () -> 0);
    FakeDecompiler secondDecompiler = new FakeDecompiler(fixture.markup, true, null, () -> 0);
    AtomicInteger created = new AtomicInteger();
    LeasePool<DecompInterface> pool = new LeasePool<>(
        2, () -> created.getAndIncrement() == 0 ? firstDecompiler : secondDecompiler);

    try (DecompilationServiceImpl service = new DecompilationServiceImpl(fixture.session, pool)) {
      service.decompileFunction("0x101000", DecompilationResource.Format.TEXT, 1_200, false);
      try (LeasePool.Lease<DecompInterface> held = pool.acquire()) {
        assertSame(firstDecompiler, held.value());
        service.decompileFunction("0x101000", DecompilationResource.Format.TEXT, 1_200, false);
      }
      assertEquals(0, firstDecompiler.flushCalls.get());
      assertEquals(0, secondDecompiler.flushCalls.get());

      modificationNumber.set(11L);
      try (LeasePool.Lease<DecompInterface> held = pool.acquire()) {
        assertSame(secondDecompiler, held.value());
        service.decompileFunction("0x101000", DecompilationResource.Format.TEXT, 1_200, false);
      }
      try (LeasePool.Lease<DecompInterface> held = pool.acquire()) {
        assertSame(firstDecompiler, held.value());
        service.decompileFunction("0x101000", DecompilationResource.Format.TEXT, 1_200, false);
      }
      assertEquals(1, firstDecompiler.flushCalls.get());
      assertEquals(1, secondDecompiler.flushCalls.get());
    }
  }

  @Test
  void constructorsRejectNullArguments() {
    Fixture fixture = createFixture(new AtomicLong(1L));
    LeasePool<DecompInterface> pool =
        new LeasePool<>(1, () -> new FakeDecompiler(fixture.markup, true, null, () -> 0));

    assertThrows(NullPointerException.class, () -> new DecompilationServiceImpl(null));
    assertThrows(NullPointerException.class, () -> new DecompilationServiceImpl(null, pool));
    assertThrows(NullPointerException.class, () -> new DecompilationServiceImpl(fixture.session, null));
  }

  @Test
  void unifiesTextAndDocumentOutputViaPrettyPrinterAndHandlesTimedOutFallback() {
    AtomicLong modificationNumber = new AtomicLong(42L);
    Fixture fixture = createFixture(modificationNumber);
    FakeDecompiler decompiler = new FakeDecompiler(fixture.markup, true, null, () -> 0);

    try (DecompilationServiceImpl service = new DecompilationServiceImpl(
        fixture.session, new LeasePool<>(1, () -> decompiler))) {
      DecompilationResource textRes =
          service.decompileFunction("0x101000", DecompilationResource.Format.TEXT, 1_200, true);
      DecompilationResource docRes =
          service.decompileFunction("0x101000", DecompilationResource.Format.DOCUMENT, 1_200, true);

      assertTrue(textRes.completed());
      assertEquals(docRes.c(), textRes.c());
      assertTrue(textRes.c().contains(
          PrettyPrinter.INDENT_STRING + "return \"semi; {brace} /*comment*/\";\n"));
      assertNull(textRes.lines());
      assertEquals(Boolean.TRUE, textRes.commentsComplete());
      assertEquals(List.of(), textRes.warnings());
    }

    FakeDecompiler timedOut = new FakeDecompiler(null, false, "Decompile timed out", () -> 0);
    timedOut.fallbackFunction = new DecompiledFunction("const char *f(void);", "/* raw fallback */");
    try (DecompilationServiceImpl service = new DecompilationServiceImpl(
        fixture.session, new LeasePool<>(1, () -> timedOut))) {
      DecompilationResource res =
          service.decompileFunction("0x101000", DecompilationResource.Format.TEXT, 1_200, false);
      assertFalse(res.completed());
      assertEquals("/* raw fallback */", res.c());
      assertEquals(List.of("Decompile timed out"), res.warnings());
    }
  }

  private static Fixture createFixture(AtomicLong modificationNumber) {
    Address entry = RAM_SPACE.getAddress(0x101000L);
    CodeUnit unit = (CodeUnit) Proxy.newProxyInstance(
        CodeUnit.class.getClassLoader(),
        new Class<?>[] {CodeUnit.class},
        (proxy, method, args) -> switch (method.getName()) {
          case "getMinAddress" -> entry;
          default -> throw new AssertionError(method.getName());
        });
    AddressIterator emptyComments = (AddressIterator) Proxy.newProxyInstance(
        AddressIterator.class.getClassLoader(),
        new Class<?>[] {AddressIterator.class},
        (proxy, method, args) -> switch (method.getName()) {
          case "iterator" -> Collections.emptyIterator();
          case "hasNext" -> false;
          default -> throw new AssertionError(method.getName());
        });
    Map<Address, Function> functions = new HashMap<>();
    Listing listing = (Listing) Proxy.newProxyInstance(
        Listing.class.getClassLoader(),
        new Class<?>[] {Listing.class},
        (proxy, method, args) -> switch (method.getName()) {
          case "getFunctionAt" -> functions.get((Address) args[0]);
          case "getCodeUnitContaining" -> unit;
          case "getCommentAddressIterator" -> {
            assertEquals(CommentType.REPEATABLE, args[0]);
            yield emptyComments;
          }
          default -> throw new AssertionError(method.getName());
        });
    Program program = (Program) Proxy.newProxyInstance(
        Program.class.getClassLoader(),
        new Class<?>[] {Program.class},
        (proxy, method, args) -> switch (method.getName()) {
          case "getModificationNumber" -> modificationNumber.get();
          case "getAddressFactory" -> ADDRESS_FACTORY;
          case "getListing" -> listing;
          case "equals" -> proxy == args[0];
          case "hashCode" -> System.identityHashCode(proxy);
          default -> throw new AssertionError(method.getName());
        });
    TestScript script = new TestScript(program);

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

    Fixture fixture = new Fixture(new GhidraSession(script), script, program, functions, markup);
    fixture.addFunction(0x101000L, "literal_demo", program);
    return fixture;
  }

  private record Fixture(
      GhidraSession session,
      TestScript script,
      Program program,
      Map<Address, Function> functions,
      ClangTokenGroup markup) {
    void addFunction(long offset, String name, Program owningProgram) {
      Address entry = RAM_SPACE.getAddress(offset);
      Function function = (Function) Proxy.newProxyInstance(
          Function.class.getClassLoader(),
          new Class<?>[] {Function.class},
          (proxy, method, args) -> switch (method.getName()) {
            case "getProgram" -> owningProgram;
            case "getEntryPoint" -> entry;
            case "getName" -> name;
            case "getBody" -> null;
            default -> throw new AssertionError(method.getName());
          });
      functions.put(entry, function);
    }
  }

  private static final class TestScript extends GhidraScript {
    private boolean hideCurrentProgram;

    private TestScript(Program program) {
      switchProgram(program);
    }

    void switchProgram(Program program) {
      set(program, TaskMonitor.DUMMY);
    }

    @Override
    public Program getCurrentProgram() {
      return hideCurrentProgram ? null : super.getCurrentProgram();
    }

    @Override
    protected void run() {}
  }

  private static final class FakeDecompiler extends DecompInterface {
    private final ClangTokenGroup markup;
    private final boolean completed;
    private final String errorMessage;
    private final IntSupplier flushAction;
    private final AtomicInteger flushCalls = new AtomicInteger();
    private final AtomicInteger decompileCalls = new AtomicInteger();
    private final AtomicInteger setOptionsCalls = new AtomicInteger();
    private int flushCallsBeforeLastDecompile = -1;
    private Program openedProgram;
    private DecompiledFunction fallbackFunction;

    private FakeDecompiler(
        ClangTokenGroup markup, boolean completed, String errorMessage, IntSupplier flushAction) {
      this.markup = markup;
      this.completed = completed;
      this.errorMessage = errorMessage;
      this.flushAction = flushAction;
    }

    @Override
    public Program getProgram() {
      return openedProgram;
    }

    @Override
    public synchronized boolean setOptions(DecompileOptions xmlOptions) {
      setOptionsCalls.incrementAndGet();
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
      decompileCalls.incrementAndGet();
      flushCallsBeforeLastDecompile = flushCalls.get();
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
