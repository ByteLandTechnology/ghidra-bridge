package app.byteland.ghidra.adapter.ghidra;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.adapter.ghidra.CppSymbolNames.DecodedSymbol;
import app.byteland.ghidra.adapter.ghidra.CppSymbolNames.NameCandidate;
import app.byteland.ghidra.adapter.ghidra.CppSymbolNames.ProgramCache;
import app.byteland.ghidra.adapter.ghidra.GhidraTestSupport.ProgramHolder;
import app.byteland.ghidra.adapter.ghidra.symbol.SymbolServiceImpl;
import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.symbol.SymbolResource;
import app.byteland.ghidra.service.symbol.SymbolService.DemangleResult;
import app.byteland.ghidra.service.symbol.SymbolService.SymbolQuery;
import ghidra.app.util.demangler.Demangled;
import ghidra.app.util.demangler.DemangledFunction;
import ghidra.app.util.demangler.DemanglerOptions;
import ghidra.app.util.demangler.MangledContext;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import java.io.ByteArrayInputStream;
import java.lang.ref.WeakReference;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class CppSymbolNamesTest {
  @BeforeAll
  static void initGhidraDemanglers() throws Exception {
    GhidraTestSupport.x64Language();
    ClassSearcher.search(TaskMonitor.DUMMY);
  }

  @Test
  void detectsItaniumAndMicrosoftNames() {
    assertTrue(CppSymbolNames.isMangled("_ZN3foo3barEv"));
    assertTrue(CppSymbolNames.isMangled("__ZN3foo3barEv"));
    assertTrue(CppSymbolNames.isMangled("?bar@foo@@QEAAXXZ"));
    assertFalse(CppSymbolNames.isMangled("main"));
    assertFalse(CppSymbolNames.isMangled("FUN_00101000"));
    assertFalse(CppSymbolNames.isMangled(null));
  }

  @Test
  void skipsTheDemanglerForPlainOrNullProgramInputs() {
    assertNull(CppSymbolNames.demangled(null, "main", null));
    assertNull(CppSymbolNames.demangled(null, "_ZN3foo3barEv", null));
  }

  @Test
  void scalesDynamicCapacityFromSymbolCountUpToCeiling() {
    assertEquals(CppSymbolNames.MIN_CAPACITY, CppSymbolNames.targetCapacity(programWithSymbols(0)));
    assertEquals(
        CppSymbolNames.MIN_CAPACITY, CppSymbolNames.targetCapacity(programWithSymbols(1_000)));
    assertEquals(10_000, CppSymbolNames.targetCapacity(programWithSymbols(8_000)));
    assertEquals(25_000, CppSymbolNames.targetCapacity(programWithSymbols(20_000)));
    assertEquals(
        CppSymbolNames.MAX_CAPACITY, CppSymbolNames.targetCapacity(programWithSymbols(200_000)));
  }

  @Test
  void raisesCapacityWhenProgramGrowsAfterInitialLookup() {
    try (ProgramHolder holder = GhidraTestSupport.createX64Program("dynamic_growth")) {
      AtomicInteger demangleProbes = new AtomicInteger();
      Program spy = spyDemanglerCalls(holder.program(), demangleProbes);
      holder.inTransaction(
          program -> program.setExecutableFormat("Executable and Linking Format (ELF)"));

      // Touch cache while symbol table is nearly empty so initial capacity is MIN_CAPACITY.
      Address base = holder.program().getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
      assertEquals("undefined seed(void)", CppSymbolNames.demangled(spy, "_Z4seedv", base));

      // Populate 6,000 mangled functions (> MIN_CAPACITY = 4,096).
      populateFunctions(holder, 6_000);

      List<String> names = new ArrayList<>(6_000);
      for (int i = 0; i < 6_000; i++) {
        String ns = "ns" + (i % 50);
        String fn = "fn_" + i;
        names.add("_ZN" + ns.length() + ns + fn.length() + fn + "Ei");
      }

      demangleProbes.set(0);
      for (String mangled : names) {
        assertNotNull(CppSymbolNames.demangled(spy, mangled, base));
      }
      int coldProbes = demangleProbes.get();
      assertTrue(coldProbes >= 6_000);

      demangleProbes.set(0);
      for (String mangled : names) {
        assertNotNull(CppSymbolNames.demangled(spy, mangled, base));
      }
      assertEquals(0, demangleProbes.get());
    }
  }

  @Test
  void hotEntriesSurviveFullScanAboveProgramCacheCeiling() {
    int ceiling = 64;
    ProgramCache cache = new ProgramCache(ceiling);
    List<String> hotKeys = new ArrayList<>();
    for (int i = 0; i < 32; i++) {
      String key = "_ZN3hot4item" + i + "Ev";
      hotKeys.add(key);
      DecodedSymbol value = new DecodedSymbol("void hot::item" + i + "()", List.of());
      cache.putIfAbsent(key, value, ceiling);
      // Second lookup promotes the entry from probation into the protected segment.
      assertNotNull(cache.get(key));
    }

    // Sweep 10x the upper limit of single-hit scan entries.
    for (int i = 0; i < ceiling * 10; i++) {
      String coldKey = "_ZN4scan5entry" + i + "Ev";
      cache.putIfAbsent(coldKey, DecodedSymbol.EMPTY, ceiling);
    }

    for (int i = 0; i < hotKeys.size(); i++) {
      DecodedSymbol retained = cache.get(hotKeys.get(i));
      assertNotNull(retained, "Expected hot entry to survive scan: " + hotKeys.get(i));
      assertEquals("void hot::item" + i + "()", retained.signature());
    }
  }

  @Test
  void hotEntriesSurviveFullTableScanAboveMaxCapacityCeiling() {
    try (ProgramHolder holder = GhidraTestSupport.createX64Program("ceiling_scan")) {
      holder.inTransaction(
          program -> program.setExecutableFormat("Executable and Linking Format (ELF)"));
      AtomicInteger demangleProbes = new AtomicInteger();
      Program spy = spyWithReportedSymbolCount(holder.program(), 100_000, demangleProbes);
      Address addr = holder.program().getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);

      List<String> hotSymbols = new ArrayList<>();
      for (int i = 0; i < 128; i++) {
        String fn = "hotFunc" + i;
        String mangled = "_ZN3hot" + fn.length() + fn + "Ei";
        hotSymbols.add(mangled);
        assertNotNull(CppSymbolNames.demangled(spy, mangled, addr));
        // Second access promotes entry into protected segment.
        assertNotNull(CppSymbolNames.demangled(spy, mangled, addr));
      }

      // Scan more single-hit mangled prefixes than MAX_CAPACITY (65,536).
      int scanCount = CppSymbolNames.MAX_CAPACITY + 8_192;
      for (int i = 0; i < scanCount; i++) {
        assertNull(CppSymbolNames.demangled(spy, "_Z_scan_only_" + i, addr));
      }

      // Every hot symbol must remain cached with zero DemanglerUtil calls.
      demangleProbes.set(0);
      for (String hot : hotSymbols) {
        assertNotNull(CppSymbolNames.demangled(spy, hot, addr));
      }
      assertEquals(0, demangleProbes.get());
    }
  }

  @Test
  void sharesPositiveNegativeAndFailureEntriesBidirectionallyWithSymbolDemangling() {
    String validMangled = "_ZN5outer5inner6widgetEii";
    String invalidMangled = "_Z_not_a_valid_cpp_name";
    String conflictMangled = "_ZN5outer5inner7blockedEv";

    // Direction 1: `CppSymbolNames.demangled` warms cache and `SymbolDemangling.apply` reuses it.
    try (ProgramHolder holder = GhidraTestSupport.createX64Program("share_read_to_write")) {
      setupSymbolsForSharing(holder, validMangled, invalidMangled, conflictMangled);
      AtomicInteger demangleProbes = new AtomicInteger();
      Program spy =
          spyWithConflictOnName(holder.program(), "blocked", "duplicate blocked symbol", demangleProbes);
      Address base = holder.program().getAddressFactory().getDefaultAddressSpace().getAddress(0x100000);

      assertEquals(
          "undefined outer::inner::widget(int,int)",
          CppSymbolNames.demangled(spy, validMangled, base));
      assertNull(CppSymbolNames.demangled(spy, invalidMangled, base.add(0x10)));
      assertEquals(
          "undefined outer::inner::blocked(void)",
          CppSymbolNames.demangled(spy, conflictMangled, base.add(0x20)));
      assertTrue(demangleProbes.get() > 0);

      // A second read of the negative entry does not invoke the demangler again.
      demangleProbes.set(0);
      assertNull(CppSymbolNames.demangled(spy, invalidMangled, base.add(0x10)));
      assertEquals(0, demangleProbes.get());

      // `symbol.demangle` reuses cached positive and negative entries with zero demangler calls.
      SymbolServiceImpl service = new SymbolServiceImpl(GhidraTestSupport.sessionFor(spy));
      DemangleResult result = service.demangleSymbols();
      assertEquals(0, demangleProbes.get());
      assertEquals(1, result.renamed());
      assertEquals(2, result.failed());
      assertEquals(
          List.of(
              invalidMangled + ": No supported C++ name",
              conflictMangled + ": duplicate blocked symbol"),
          result.failures());
    }

    // Direction 2: `SymbolDemangling.apply` warms cache and `symbol.list` hits the cache.
    try (ProgramHolder holder = GhidraTestSupport.createX64Program("share_write_to_read")) {
      setupSymbolsForSharing(holder, validMangled, invalidMangled, null);
      AtomicInteger demangleProbes = new AtomicInteger();
      Program spy = spyDemanglerCalls(holder.program(), demangleProbes);
      SymbolServiceImpl service = new SymbolServiceImpl(GhidraTestSupport.sessionFor(spy));

      DemangleResult result = service.demangleSymbols();
      assertEquals(1, result.renamed());
      assertEquals(1, result.failed());
      assertEquals(List.of(invalidMangled + ": No supported C++ name"), result.failures());
      assertTrue(demangleProbes.get() > 0);

      // Post-demangle symbol.list visits primary renamed symbol ("widget"), retained secondary
      // mangled label ("_ZN5outer5inner6widgetEii"), and unrenamed invalid mangled symbol.
      demangleProbes.set(0);
      Page<SymbolResource> symbols =
          service.listSymbols(
              new SymbolQuery(
                  AddressScanOptions.of(null, null, 10_000),
                  null,
                  null,
                  null,
                  null,
                  null,
                  false,
                  100,
                  null));
      assertEquals(0, demangleProbes.get());

      SymbolResource primaryWidget =
          symbols.items().stream()
              .filter(item -> "widget".equals(item.name()) && item.primary())
              .findFirst()
              .orElseThrow();
      assertEquals("outer::inner", primaryWidget.namespace());
      assertNull(primaryWidget.demangledName());

      SymbolResource secondaryMangled =
          symbols.items().stream()
              .filter(item -> validMangled.equals(item.name()) && !item.primary())
              .findFirst()
              .orElseThrow();
      assertEquals("undefined outer::inner::widget(int,int)", secondaryMangled.demangledName());
    }
  }

  @Test
  void concurrentCachedReadsDoNotBlockDuringSlowCacheMiss() throws Exception {
    try (ProgramHolder holder = GhidraTestSupport.createX64Program("concurrent_reads")) {
      holder.inTransaction(
          program -> program.setExecutableFormat("Executable and Linking Format (ELF)"));
      Address addr = holder.program().getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
      CountDownLatch enteredMissDemangle = new CountDownLatch(1);
      CountDownLatch releaseMissDemangle = new CountDownLatch(1);
      AtomicBoolean blockNextFormatRead = new AtomicBoolean(false);

      Program spy =
          (Program)
              Proxy.newProxyInstance(
                  Program.class.getClassLoader(),
                  new Class<?>[] {Program.class},
                  (proxy, method, args) -> {
                    if ("getExecutableFormat".equals(method.getName())
                        && blockNextFormatRead.compareAndSet(true, false)) {
                      enteredMissDemangle.countDown();
                      if (!releaseMissDemangle.await(5, TimeUnit.SECONDS)) {
                        throw new IllegalStateException("Timed out waiting to release miss");
                      }
                    }
                    try {
                      return method.invoke(holder.program(), args);
                    } catch (InvocationTargetException error) {
                      throw error.getTargetException();
                    }
                  });

      String cachedKey = "_ZN4fast3hitEi";
      assertEquals("undefined fast::hit(int)", CppSymbolNames.demangled(spy, cachedKey, addr));

      blockNextFormatRead.set(true);
      try (ExecutorService pool = Executors.newFixedThreadPool(5)) {
        Future<String> slowMiss =
            pool.submit(() -> CppSymbolNames.demangled(spy, "_ZN4slow4missEi", addr));
        assertTrue(enteredMissDemangle.await(5, TimeUnit.SECONDS));

        List<Future<?>> readers = new ArrayList<>();
        for (int t = 0; t < 4; t++) {
          readers.add(
              pool.submit(
                  () -> {
                    for (int i = 0; i < 500; i++) {
                      assertEquals(
                          "undefined fast::hit(int)",
                          CppSymbolNames.demangled(spy, cachedKey, addr));
                    }
                  }));
        }
        for (Future<?> reader : readers) {
          reader.get(2, TimeUnit.SECONDS);
        }

        releaseMissDemangle.countDown();
        assertEquals("undefined slow::miss(int)", slowMiss.get(5, TimeUnit.SECONDS));
      }
    }
  }

  @Test
  void stripsMangledContextAndProgramReferencesSoClosedProgramsCollect() throws Exception {
    GcProbe probe = createDecodeAndCloseProgram();
    assertNotNull(probe.retainedDecoded().signature());
    assertFalse(probe.retainedDecoded().candidates().isEmpty());
    for (NameCandidate candidate : probe.retainedDecoded().candidates()) {
      Demangled current = candidate.namespace();
      assertNotNull(current);
      while (current != null) {
        assertNull(current.getMangledContext());
        current = current.getNamespace();
      }
    }
    assertNull(probe.detachedSyntheticFunctionNamespace().getMangledContext());

    for (int attempt = 0; attempt < 40 && probe.programRef().get() != null; attempt++) {
      byte[] pressure = new byte[512 * 1024];
      pressure[0] = (byte) attempt;
      System.gc();
      Thread.sleep(25);
    }
    assertNull(probe.programRef().get(), "Closed Program remained strongly reachable");

      // Trigger stale key cleanup on a live program.
      try (ProgramHolder next = GhidraTestSupport.createX64Program("gc_cleanup_followup")) {
        next.inTransaction(
            program -> program.setExecutableFormat("Executable and Linking Format (ELF)"));
        Address addr =
            next.program().getAddressFactory().getDefaultAddressSpace().getAddress(0x1000);
        assertEquals(
            "undefined ping(void)", CppSymbolNames.demangled(next.program(), "_Z4pingv", addr));
      }
    }

  private static GcProbe createDecodeAndCloseProgram() {
    String localStaticInFunction = "_ZZN5alpha3runEiE7counter";
    try (ProgramHolder holder = GhidraTestSupport.createX64Program("gc_collectible_program")) {
      Program program = holder.program();
      Address base = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x00100000L);
      holder.inTransaction(
          db -> {
            db.setExecutableFormat("Executable and Linking Format (ELF)");
            db.getMemory()
                .createInitializedBlock(
                    ".text",
                    base,
                    new ByteArrayInputStream(new byte[] {(byte) 0x90, (byte) 0xc3, 0, 0, 0, 0, 0, 0}),
                    8,
                    TaskMonitor.DUMMY,
                    false);
            db.getFunctionManager()
                .createFunction(
                    "_ZN5alpha4beta5gammaEv",
                    base,
                    new AddressSet(base, base.add(1)),
                    SourceType.IMPORTED);
            db.getSymbolTable()
                .createLabel(base.add(4), localStaticInFunction, SourceType.IMPORTED);
          });

      DecodedSymbol retained = CppSymbolNames.decode(program, localStaticInFunction, base.add(4));
      SymbolServiceImpl symService = new SymbolServiceImpl(GhidraTestSupport.sessionFor(program));
      DemangleResult result = symService.demangleSymbols();
      assertEquals(2, result.renamed());

      // Also verify explicit MangledContext removal on a DemangledFunction namespace node.
      DemangledFunction rawFnNamespace =
          new DemangledFunction("_ZN5alpha3runEi", "alpha::run(int)", "run");
      rawFnNamespace.setMangledContext(
          new MangledContext(program, new DemanglerOptions(), "_ZN5alpha3runEi", base));
      NameCandidate explicitCandidate =
          new NameCandidate("alpha::run(int)::counter", "counter", rawFnNamespace);

      return new GcProbe(
          new WeakReference<>(program), retained, explicitCandidate.namespace());
    }
  }

  private record GcProbe(
      WeakReference<Program> programRef,
      DecodedSymbol retainedDecoded,
      Demangled detachedSyntheticFunctionNamespace) {}

  private static void populateFunctions(ProgramHolder holder, int count) {
    holder.inTransaction(
        program -> {
          AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
          Address base = space.getAddress(0x00200000L);
          byte[] code = new byte[count * 2];
          for (int i = 0; i < count; i++) {
            code[i * 2] = (byte) 0x90;
            code[i * 2 + 1] = (byte) 0xc3;
          }
          program
              .getMemory()
              .createInitializedBlock(
                  ".text",
                  base,
                  new ByteArrayInputStream(code),
                  code.length,
                  TaskMonitor.DUMMY,
                  false);
          FunctionManager fm = program.getFunctionManager();
          for (int i = 0; i < count; i++) {
            Address entry = base.add(i * 2L);
            String ns = "ns" + (i % 50);
            String fn = "fn_" + i;
            String mangled = "_ZN" + ns.length() + ns + fn.length() + fn + "Ei";
            fm.createFunction(
                mangled, entry, new AddressSet(entry, entry.add(1)), SourceType.IMPORTED);
          }
        });
  }

  private static void setupSymbolsForSharing(
      ProgramHolder holder, String validMangled, String invalidMangled, String conflictMangled) {
    holder.inTransaction(
        program -> {
          program.setExecutableFormat("Executable and Linking Format (ELF)");
          AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
          Address base = space.getAddress(0x00100000L);
          byte[] code = new byte[64];
          code[0] = (byte) 0x90;
          code[1] = (byte) 0xc3;
          code[0x10] = (byte) 0x90;
          code[0x11] = (byte) 0xc3;
          code[0x20] = (byte) 0x90;
          code[0x21] = (byte) 0xc3;
          program
              .getMemory()
              .createInitializedBlock(
                  ".text",
                  base,
                  new ByteArrayInputStream(code),
                  code.length,
                  TaskMonitor.DUMMY,
                  false);
          FunctionManager fm = program.getFunctionManager();
          fm.createFunction(
              validMangled, base, new AddressSet(base, base.add(1)), SourceType.IMPORTED);
          Symbol invalid =
              program
                  .getSymbolTable()
                  .createLabel(base.add(0x10), invalidMangled, SourceType.IMPORTED);
          invalid.setPrimary();
          if (conflictMangled != null) {
            Symbol conflict =
                program
                    .getSymbolTable()
                    .createLabel(base.add(0x20), conflictMangled, SourceType.IMPORTED);
            conflict.setPrimary();
          }
        });
  }

  private static Program programWithSymbols(int count) {
    SymbolTable table =
        (SymbolTable)
            Proxy.newProxyInstance(
                SymbolTable.class.getClassLoader(),
                new Class<?>[] {SymbolTable.class},
                (proxy, method, args) -> {
                  if ("getNumSymbols".equals(method.getName())) return count;
                  throw new AssertionError("Unexpected SymbolTable method: " + method.getName());
                });
    return (Program)
        Proxy.newProxyInstance(
            Program.class.getClassLoader(),
            new Class<?>[] {Program.class},
            (proxy, method, args) -> {
              if ("getSymbolTable".equals(method.getName())) return table;
              throw new AssertionError("Unexpected Program method: " + method.getName());
            });
  }

  private static Program spyDemanglerCalls(Program delegate, AtomicInteger executableFormatCalls) {
    Program[] box = new Program[1];
    SymbolTable realTable = delegate.getSymbolTable();
    SymbolTable tableProxy =
        (SymbolTable)
            Proxy.newProxyInstance(
                SymbolTable.class.getClassLoader(),
                new Class<?>[] {SymbolTable.class},
                (proxy, method, args) -> {
                  Object result;
                  try {
                    result = method.invoke(realTable, args);
                  } catch (InvocationTargetException error) {
                    throw error.getTargetException();
                  }
                  if (result instanceof SymbolIterator iter) {
                    return wrapSymbolIterator(iter, box[0]);
                  }
                  if (result instanceof Symbol sym) {
                    return wrapSymbol(sym, box[0]);
                  }
                  return result;
                });
    box[0] =
        (Program)
            Proxy.newProxyInstance(
                Program.class.getClassLoader(),
                new Class<?>[] {Program.class},
                (proxy, method, args) -> {
                  if ("getExecutableFormat".equals(method.getName())) {
                    executableFormatCalls.incrementAndGet();
                  }
                  if ("getSymbolTable".equals(method.getName())) return tableProxy;
                  try {
                    return method.invoke(delegate, args);
                  } catch (InvocationTargetException error) {
                    throw error.getTargetException();
                  }
                });
    return box[0];
  }

  private static SymbolIterator wrapSymbolIterator(SymbolIterator delegate, Program owner) {
    return (SymbolIterator)
        Proxy.newProxyInstance(
            SymbolIterator.class.getClassLoader(),
            new Class<?>[] {SymbolIterator.class},
            (proxy, method, args) -> {
              Object result;
              try {
                result = method.invoke(delegate, args);
              } catch (InvocationTargetException error) {
                throw error.getTargetException();
              }
              if (result instanceof Symbol sym) {
                return wrapSymbol(sym, owner);
              }
              return result;
            });
  }

  private static Symbol wrapSymbol(Symbol delegate, Program owner) {
    return (Symbol)
        Proxy.newProxyInstance(
            Symbol.class.getClassLoader(),
            new Class<?>[] {Symbol.class},
            (proxy, method, args) -> {
              if ("getProgram".equals(method.getName())) return owner;
              try {
                return method.invoke(delegate, args);
              } catch (InvocationTargetException error) {
                throw error.getTargetException();
              }
            });
  }

  private static Program spyWithReportedSymbolCount(
      Program delegate, int reportedCount, AtomicInteger executableFormatCalls) {
    SymbolTable realTable = delegate.getSymbolTable();
    SymbolTable tableProxy =
        (SymbolTable)
            Proxy.newProxyInstance(
                SymbolTable.class.getClassLoader(),
                new Class<?>[] {SymbolTable.class},
                (proxy, method, args) -> {
                  if ("getNumSymbols".equals(method.getName())) return reportedCount;
                  try {
                    return method.invoke(realTable, args);
                  } catch (InvocationTargetException error) {
                    throw error.getTargetException();
                  }
                });
    return (Program)
        Proxy.newProxyInstance(
            Program.class.getClassLoader(),
            new Class<?>[] {Program.class},
            (proxy, method, args) -> {
              if ("getExecutableFormat".equals(method.getName())) {
                executableFormatCalls.incrementAndGet();
              }
              if ("getSymbolTable".equals(method.getName())) return tableProxy;
              try {
                return method.invoke(delegate, args);
              } catch (InvocationTargetException error) {
                throw error.getTargetException();
              }
            });
  }

  private static Program spyWithConflictOnName(
      Program delegate,
      String rejectedSymbolName,
      String errorMessage,
      AtomicInteger executableFormatCalls) {
    SymbolTable realTable = delegate.getSymbolTable();
    SymbolTable tableProxy =
        (SymbolTable)
            Proxy.newProxyInstance(
                SymbolTable.class.getClassLoader(),
                new Class<?>[] {SymbolTable.class},
                (proxy, method, args) -> {
                  if ("createLabel".equals(method.getName())
                      && args != null
                      && args.length >= 2
                      && rejectedSymbolName.equals(args[1])) {
                    throw new InvalidInputException(errorMessage);
                  }
                  try {
                    return method.invoke(realTable, args);
                  } catch (InvocationTargetException error) {
                    throw error.getTargetException();
                  }
                });
    return (Program)
        Proxy.newProxyInstance(
            Program.class.getClassLoader(),
            new Class<?>[] {Program.class},
            (proxy, method, args) -> {
              if ("getExecutableFormat".equals(method.getName())) {
                executableFormatCalls.incrementAndGet();
              }
              if ("getSymbolTable".equals(method.getName())) return tableProxy;
              try {
                return method.invoke(delegate, args);
              } catch (InvocationTargetException error) {
                throw error.getTargetException();
              }
            });
  }
}
