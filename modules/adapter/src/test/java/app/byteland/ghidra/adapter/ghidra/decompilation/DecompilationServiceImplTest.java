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
import ghidra.app.decompiler.DecompileProcess;
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
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class DecompilationServiceImplTest {
  private static final AddressSpace RAM_SPACE =
      new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 0);
  private static final AddressFactory ADDRESS_FACTORY =
      new DefaultAddressFactory(new AddressSpace[] {RAM_SPACE}, RAM_SPACE);

  private static final class TestScript extends GhidraScript {
    private boolean hideCurrentProgram;

    private TestScript(Program program) {
      switchProgram(program);
    }

    void switchProgram(Program program) {
      set(program, TaskMonitor.DUMMY);
    }

    void setHideCurrentProgram(boolean hideCurrentProgram) {
      this.hideCurrentProgram = hideCurrentProgram;
    }

    @Override
    public Program getCurrentProgram() {
      return hideCurrentProgram ? null : super.getCurrentProgram();
    }

    @Override
    protected void run() {}
  }

  private static final class StubProgram {
    private final AtomicLong modificationNumber;
    private final Map<Address, Function> functions = new HashMap<>();
    private final Program proxy;

    private StubProgram(long initialModificationNumber) {
      this.modificationNumber = new AtomicLong(initialModificationNumber);
      AddressIterator emptyComments =
          (AddressIterator)
              Proxy.newProxyInstance(
                  AddressIterator.class.getClassLoader(),
                  new Class<?>[] {AddressIterator.class},
                  (instance, method, args) ->
                      switch (method.getName()) {
                        case "iterator" -> Collections.emptyIterator();
                        case "hasNext" -> false;
                        default ->
                            throw new AssertionError("Unexpected AddressIterator call: " + method);
                      });
      Listing listing =
          (Listing)
              Proxy.newProxyInstance(
                  Listing.class.getClassLoader(),
                  new Class<?>[] {Listing.class},
                  (instance, method, args) ->
                      switch (method.getName()) {
                        case "getFunctionAt" -> functions.get((Address) args[0]);
                        case "getCommentAddressIterator" -> emptyComments;
                        case "equals" -> instance == args[0];
                        case "hashCode" -> System.identityHashCode(instance);
                        case "toString" -> "StubListing";
                        default -> throw new AssertionError("Unexpected Listing call: " + method);
                      });
      this.proxy =
          (Program)
              Proxy.newProxyInstance(
                  Program.class.getClassLoader(),
                  new Class<?>[] {Program.class},
                  (instance, method, args) ->
                      switch (method.getName()) {
                        case "getModificationNumber" -> modificationNumber.get();
                        case "getAddressFactory" -> ADDRESS_FACTORY;
                        case "getListing" -> listing;
                        case "equals" -> instance == args[0];
                        case "hashCode" -> System.identityHashCode(instance);
                        case "toString" ->
                            "StubProgram@" + Integer.toHexString(System.identityHashCode(instance));
                        default -> throw new AssertionError("Unexpected Program call: " + method);
                      });
    }

    Function addFunction(long offset, String initialName) {
      return addFunctionWithProgram(offset, initialName, proxy);
    }

    Function addOrphanFunction(long offset, String initialName) {
      return addFunctionWithProgram(offset, initialName, null);
    }

    private Function addFunctionWithProgram(
        long offset, String initialName, Program owningProgram) {
      Address entry = RAM_SPACE.getAddress(offset);
      final String[] currentName = {initialName};
      Function fn =
          (Function)
              Proxy.newProxyInstance(
                  Function.class.getClassLoader(),
                  new Class<?>[] {Function.class},
                  (instance, method, args) ->
                      switch (method.getName()) {
                        case "getProgram" -> owningProgram;
                        case "getEntryPoint" -> entry;
                        case "getName" -> currentName[0];
                        case "getBody" -> null;
                        case "setName" -> {
                          currentName[0] = (String) args[0];
                          modificationNumber.incrementAndGet();
                          yield null;
                        }
                        case "equals" -> instance == args[0];
                        case "hashCode" -> System.identityHashCode(instance);
                        case "toString" -> "StubFunction(" + currentName[0] + ")";
                        default -> throw new AssertionError("Unexpected Function call: " + method);
                      });
      functions.put(entry, fn);
      return fn;
    }

    void setModificationNumber(long value) {
      modificationNumber.set(value);
    }

    long incrementModificationNumber() {
      return modificationNumber.incrementAndGet();
    }

    Program program() {
      return proxy;
    }
  }

  private static final class StubDecompileResults extends DecompileResults {
    private final DecompiledFunction decompiledFunction;

    private StubDecompileResults(Function function, String code) {
      super(function, null, null, null, "", null, DecompileProcess.DisposeState.NOT_DISPOSED);
      this.decompiledFunction =
          new DecompiledFunction("void " + function.getName() + "(void)", code);
    }

    @Override
    public boolean decompileCompleted() {
      return true;
    }

    @Override
    public String getErrorMessage() {
      return "";
    }

    @Override
    public ClangTokenGroup getCCodeMarkup() {
      return null;
    }

    @Override
    public DecompiledFunction getDecompiledFunction() {
      return decompiledFunction;
    }
  }

  private static final class RecordingDecompiler extends DecompInterface {
    private final AtomicInteger flushCalls = new AtomicInteger();
    private final AtomicInteger decompileCalls = new AtomicInteger();
    private final AtomicInteger setOptionsCalls = new AtomicInteger();
    private int flushCallsSeenAtLastDecompile = -1;
    private RuntimeException nextFlushFailure;
    private int nextFlushStatus;

    @Override
    public synchronized boolean setOptions(DecompileOptions xmlOptions) {
      setOptionsCalls.incrementAndGet();
      return true;
    }

    @Override
    public synchronized int flushCache() {
      flushCalls.incrementAndGet();
      if (nextFlushFailure != null) {
        RuntimeException failure = nextFlushFailure;
        nextFlushFailure = null;
        throw failure;
      }
      int status = nextFlushStatus;
      nextFlushStatus = 0;
      return status;
    }

    @Override
    public synchronized DecompileResults decompileFunction(
        Function func, int timeoutSecs, TaskMonitor monitor) {
      decompileCalls.incrementAndGet();
      flushCallsSeenAtLastDecompile = flushCalls.get();
      String code = "void " + func.getName() + "(void)\n{\n  return;\n}\n";
      return new StubDecompileResults(func, code);
    }

    void failNextFlush(RuntimeException failure) {
      this.nextFlushFailure = failure;
    }

    void returnNextFlushStatus(int status) {
      this.nextFlushStatus = status;
    }

    int flushCount() {
      return flushCalls.get();
    }

    int decompileCount() {
      return decompileCalls.get();
    }

    int setOptionsCount() {
      return setOptionsCalls.get();
    }

    int flushCountBeforeLastDecompile() {
      return flushCallsSeenAtLastDecompile;
    }
  }

  @Test
  @DisplayName("Cold decompile records initial program state without calling flushCache")
  void coldCallDoesNotFlushAndRepeatedReadsKeepNativeCache() {
    StubProgram stubProgram = new StubProgram(10L);
    stubProgram.addFunction(0x1000L, "alpha");
    stubProgram.addFunction(0x2000L, "beta");

    RecordingDecompiler decompiler = new RecordingDecompiler();
    LeasePool<DecompInterface> pool = new LeasePool<>(1, () -> decompiler);
    GhidraSession session = new GhidraSession(new TestScript(stubProgram.program()));

    try (DecompilationServiceImpl service = new DecompilationServiceImpl(session, pool)) {
      DecompilationResource first =
          service.decompileFunction("0x1000", DecompilationResource.Format.TEXT, null, false);
      assertEquals("alpha", first.name());
      assertTrue(first.c().contains("alpha"));
      assertEquals(0, decompiler.flushCount());
      assertEquals(1, decompiler.decompileCount());
      assertEquals(1, decompiler.setOptionsCount());

      // Repeated read-only calls on the same or another function must not flush.
      DecompilationResource second =
          service.decompileFunction("0x1000", DecompilationResource.Format.TEXT, null, false);
      DecompilationResource third =
          service.decompileFunction("0x2000", DecompilationResource.Format.TOKENS, null, false);
      assertEquals("alpha", second.name());
      assertEquals("beta", third.name());
      assertEquals(0, decompiler.flushCount());
      assertEquals(3, decompiler.decompileCount());
      assertEquals(1, decompiler.setOptionsCount());
    }
  }

  @Test
  @DisplayName("Program modification triggers exactly one flushCache before decompileFunction")
  void programMutationFlushesOnceThenResumesCaching() throws Exception {
    StubProgram stubProgram = new StubProgram(100L);
    Function fn = stubProgram.addFunction(0x1000L, "before_rename");

    RecordingDecompiler decompiler = new RecordingDecompiler();
    LeasePool<DecompInterface> pool = new LeasePool<>(1, () -> decompiler);
    GhidraSession session = new GhidraSession(new TestScript(stubProgram.program()));

    try (DecompilationServiceImpl service = new DecompilationServiceImpl(session, pool)) {
      DecompilationResource initial =
          service.decompileFunction("0x1000", DecompilationResource.Format.TEXT, null, false);
      assertTrue(initial.c().contains("before_rename"));
      assertEquals(0, decompiler.flushCount());

      fn.setName("after_rename", null);
      assertEquals(101L, stubProgram.program().getModificationNumber());

      DecompilationResource updated =
          service.decompileFunction("0x1000", DecompilationResource.Format.TEXT, null, false);
      assertTrue(updated.c().contains("after_rename"));
      assertEquals(1, decompiler.flushCount());
      assertEquals(1, decompiler.flushCountBeforeLastDecompile());

      // Subsequent reads at modificationNumber=101 must not flush again.
      service.decompileFunction("0x1000", DecompilationResource.Format.TEXT, null, false);
      assertEquals(1, decompiler.flushCount());
      assertEquals(3, decompiler.decompileCount());
    }
  }

  @Test
  void flushesCacheOnlyWhenProgramModificationNumberChangesAcrossFormats() {
    AtomicLong modificationNumber = new AtomicLong(10L);
    Fixture fixture = createFixture(modificationNumber);
    FakeDecompiler decompiler = new FakeDecompiler(fixture.markup, true, null, () -> 0);

    try (DecompilationServiceImpl service =
        new DecompilationServiceImpl(fixture.session, new LeasePool<>(1, () -> decompiler))) {
      service.decompileFunction("0x101000", DecompilationResource.Format.TEXT, 1_200, false);
      assertEquals(0, decompiler.flushCalls.get());

      // Repeated reads at the same modification number skip cache flushes.
      service.decompileFunction("0x101000", DecompilationResource.Format.TEXT, 1_200, false);
      service.decompileFunction("0x101000", DecompilationResource.Format.DOCUMENT, 1_200, true);
      assertEquals(0, decompiler.flushCalls.get());

      // Advancing the program modification number triggers a new flush once.
      modificationNumber.set(11L);
      service.decompileFunction("0x101000", DecompilationResource.Format.TEXT, 1_200, true);
      assertEquals(1, decompiler.flushCalls.get());

      service.decompileFunction("0x101000", DecompilationResource.Format.TOKENS, 1_200, true);
      assertEquals(1, decompiler.flushCalls.get());
    }
  }

  @Test
  @DisplayName("Transaction rollback or undo decrementing modificationNumber flushes cache")
  void rollbackOrUndoModificationNumberInequalityFlushesCache() {
    StubProgram stubProgram = new StubProgram(50L);
    stubProgram.addFunction(0x1000L, "target");

    RecordingDecompiler decompiler = new RecordingDecompiler();
    LeasePool<DecompInterface> pool = new LeasePool<>(1, () -> decompiler);
    GhidraSession session = new GhidraSession(new TestScript(stubProgram.program()));

    try (DecompilationServiceImpl service = new DecompilationServiceImpl(session, pool)) {
      // Initial read at mod=50.
      service.decompileFunction("0x1000", DecompilationResource.Format.TEXT, null, false);
      assertEquals(0, decompiler.flushCount());

      // Uncommitted edit inside a batch advances mod to 51; read observes mod=51 and flushes.
      stubProgram.setModificationNumber(51L);
      service.decompileFunction("0x1000", DecompilationResource.Format.TEXT, null, false);
      assertEquals(1, decompiler.flushCount());

      // Rollback or GUI undo reverts modificationNumber from 51 back to 50 (< 51).
      stubProgram.setModificationNumber(50L);
      service.decompileFunction("0x1000", DecompilationResource.Format.TEXT, null, false);
      assertEquals(2, decompiler.flushCount());

      // Stable again at mod=50.
      service.decompileFunction("0x1000", DecompilationResource.Format.TEXT, null, false);
      assertEquals(2, decompiler.flushCount());
    }
  }

  @Test
  @DisplayName("Switching Program reference flushes cache even when modificationNumber matches")
  void programReferenceChangeFlushesCacheEvenWithSameModificationNumber() {
    StubProgram programA = new StubProgram(7L);
    programA.addFunction(0x1000L, "from_program_a");

    StubProgram programB = new StubProgram(7L);
    programB.addFunction(0x1000L, "from_program_b");

    RecordingDecompiler decompiler = new RecordingDecompiler();
    LeasePool<DecompInterface> pool = new LeasePool<>(1, () -> decompiler);
    TestScript script = new TestScript(programA.program());
    GhidraSession session = new GhidraSession(script);

    try (DecompilationServiceImpl service = new DecompilationServiceImpl(session, pool)) {
      DecompilationResource first =
          service.decompileFunction("0x1000", DecompilationResource.Format.TEXT, null, false);
      assertTrue(first.c().contains("from_program_a"));
      assertEquals(0, decompiler.flushCount());

      // Switch to a distinct Program with the exact same modificationNumber (7L).
      script.switchProgram(programB.program());
      DecompilationResource second =
          service.decompileFunction("0x1000", DecompilationResource.Format.TEXT, null, false);
      assertTrue(second.c().contains("from_program_b"));
      assertEquals(1, decompiler.flushCount());
      assertEquals(1, decompiler.flushCountBeforeLastDecompile());

      // Repeated read on programB does not flush again.
      service.decompileFunction("0x1000", DecompilationResource.Format.TEXT, null, false);
      assertEquals(1, decompiler.flushCount());
    }
  }

  @Test
  @DisplayName(
      "Failed flushCache keeps dirty state and retries even after rollback to prior modificationNumber")
  void flushFailureKeepsDirtyFlagUntilSubsequentFlushSucceeds() {
    StubProgram stubProgram = new StubProgram(20L);
    stubProgram.addFunction(0x1000L, "fn");

    RecordingDecompiler decompiler = new RecordingDecompiler();
    LeasePool<DecompInterface> pool = new LeasePool<>(1, () -> decompiler);
    GhidraSession session = new GhidraSession(new TestScript(stubProgram.program()));

    try (DecompilationServiceImpl service = new DecompilationServiceImpl(session, pool)) {
      // Cold read records mod=20.
      service.decompileFunction("0x1000", DecompilationResource.Format.TEXT, null, false);
      assertEquals(0, decompiler.flushCount());
      assertEquals(1, decompiler.decompileCount());

      // Mutate to mod=21 and inject a flush failure.
      stubProgram.incrementModificationNumber();
      IllegalStateException boom = new IllegalStateException("native flush failed");
      decompiler.failNextFlush(boom);
      IllegalStateException thrown =
          assertThrows(
              IllegalStateException.class,
              () ->
                  service.decompileFunction(
                      "0x1000", DecompilationResource.Format.TEXT, null, false));
      assertSame(boom, thrown);
      assertEquals(1, decompiler.flushCount());
      // decompileFunction must not be called when flushCache throws.
      assertEquals(1, decompiler.decompileCount());

      // Even if modificationNumber rolls back to 20 (matching the pre-failure number),
      // the dirty flag must force a retry flush on the next call.
      stubProgram.setModificationNumber(20L);
      decompiler.returnNextFlushStatus(-1);
      service.decompileFunction("0x1000", DecompilationResource.Format.TEXT, null, false);
      assertEquals(2, decompiler.flushCount());
      assertEquals(2, decompiler.decompileCount());

      // Negative flushCache return value keeps dirty flag set until a >= 0 flush succeeds.
      service.decompileFunction("0x1000", DecompilationResource.Format.TEXT, null, false);
      assertEquals(3, decompiler.flushCount());
      assertEquals(3, decompiler.decompileCount());

      // Once the retry flush succeeds, subsequent reads at mod=20 do not flush.
      service.decompileFunction("0x1000", DecompilationResource.Format.TEXT, null, false);
      assertEquals(3, decompiler.flushCount());
      assertEquals(4, decompiler.decompileCount());
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
            () ->
                switch (mode.get()) {
                  case 1 -> throw new IllegalStateException("ipc broken");
                  case 2 -> -1;
                  default -> 0;
                });

    try (DecompilationServiceImpl service =
        new DecompilationServiceImpl(fixture.session, new LeasePool<>(1, () -> decompiler))) {
      service.decompileFunction("0x101000", DecompilationResource.Format.TEXT, 1_000, false);
      assertEquals(0, decompiler.flushCalls.get());

      // Modification changes to 2, and flushCache throws while state is marked dirty.
      modificationNumber.set(2L);
      mode.set(1);
      assertThrows(
          IllegalStateException.class,
          () ->
              service.decompileFunction(
                  "0x101000", DecompilationResource.Format.TEXT, 1_000, false));
      assertEquals(1, decompiler.flushCalls.get());

      // Next lease at the same modification 2 retries flushCache; negative status keeps it dirty.
      mode.set(2);
      service.decompileFunction("0x101000", DecompilationResource.Format.TEXT, 1_000, false);
      assertEquals(2, decompiler.flushCalls.get());

      // Once flushCache succeeds (>= 0), modification 2 is cached and subsequent reads skip flush.
      mode.set(0);
      service.decompileFunction("0x101000", DecompilationResource.Format.TEXT, 1_000, false);
      assertEquals(3, decompiler.flushCalls.get());

      service.decompileFunction("0x101000", DecompilationResource.Format.TEXT, 1_000, false);
      assertEquals(3, decompiler.flushCalls.get());
    }
  }

  @Test
  @DisplayName("Missing Program flushes defensively and marks decompiler dirty for next Program")
  void flushesWhenProgramIsAbsentAndMarksDecompilerDirtyForNextProgram() {
    StubProgram stubProgram = new StubProgram(15L);
    stubProgram.addFunction(0x1000L, "attached");
    stubProgram.addOrphanFunction(0x2000L, "orphan");

    RecordingDecompiler decompiler = new RecordingDecompiler();
    LeasePool<DecompInterface> pool = new LeasePool<>(1, () -> decompiler);
    TestScript script = new TestScript(stubProgram.program());
    GhidraSession session = new GhidraSession(script);

    try (DecompilationServiceImpl service = new DecompilationServiceImpl(session, pool)) {
      service.decompileFunction("0x1000", DecompilationResource.Format.TEXT, null, false);
      assertEquals(0, decompiler.flushCount());

      script.setHideCurrentProgram(true);
      DecompilationResource orphanRes =
          service.decompileFunction("0x2000", DecompilationResource.Format.TEXT, null, false);
      assertEquals("orphan", orphanRes.name());
      assertEquals(1, decompiler.flushCount());

      // Restoring the same Program at the same modificationNumber=15L must still flush once.
      script.setHideCurrentProgram(false);
      service.decompileFunction("0x1000", DecompilationResource.Format.TEXT, null, false);
      assertEquals(2, decompiler.flushCount());

      service.decompileFunction("0x1000", DecompilationResource.Format.TEXT, null, false);
      assertEquals(2, decompiler.flushCount());
    }
  }

  @Test
  @DisplayName("Cache state is tracked independently per pooled DecompInterface instance")
  void tracksCacheStatePerPooledDecompiler() throws Exception {
    StubProgram stubProgram = new StubProgram(10L);
    stubProgram.addFunction(0x1000L, "fn");

    RecordingDecompiler firstDecompiler = new RecordingDecompiler();
    RecordingDecompiler secondDecompiler = new RecordingDecompiler();
    AtomicInteger created = new AtomicInteger();
    LeasePool<DecompInterface> pool =
        new LeasePool<>(
            2, () -> created.getAndIncrement() == 0 ? firstDecompiler : secondDecompiler);
    GhidraSession session = new GhidraSession(new TestScript(stubProgram.program()));

    try (DecompilationServiceImpl service = new DecompilationServiceImpl(session, pool)) {
      // Hold lease on firstDecompiler briefly via service call, then hold firstDecompiler externally
      // so the second slot is initialized at mod=10 as well.
      service.decompileFunction("0x1000", DecompilationResource.Format.TEXT, null, false);
      try (LeasePool.Lease<DecompInterface> held = pool.acquire()) {
        assertSame(firstDecompiler, held.value());
        service.decompileFunction("0x1000", DecompilationResource.Format.TEXT, null, false);
      }
      assertEquals(0, firstDecompiler.flushCount());
      assertEquals(0, secondDecompiler.flushCount());

      // Mutate to mod=11: hold each slot in turn so both pooled instances decompile at mod=11.
      stubProgram.setModificationNumber(11L);
      try (LeasePool.Lease<DecompInterface> held = pool.acquire()) {
        service.decompileFunction("0x1000", DecompilationResource.Format.TEXT, null, false);
      }
      try (LeasePool.Lease<DecompInterface> held = pool.acquire()) {
        service.decompileFunction("0x1000", DecompilationResource.Format.TEXT, null, false);
      }
      assertEquals(1, firstDecompiler.flushCount());
      assertEquals(1, secondDecompiler.flushCount());
    }
  }

  @Test
  @DisplayName("Constructors reject null arguments")
  void constructorsRejectNullArguments() {
    StubProgram stubProgram = new StubProgram(1L);
    GhidraSession session = new GhidraSession(new TestScript(stubProgram.program()));
    LeasePool<DecompInterface> pool = new LeasePool<>(1, RecordingDecompiler::new);

    assertThrows(NullPointerException.class, () -> new DecompilationServiceImpl(null));
    assertThrows(NullPointerException.class, () -> new DecompilationServiceImpl(null, pool));
    assertThrows(NullPointerException.class, () -> new DecompilationServiceImpl(session, null));
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
