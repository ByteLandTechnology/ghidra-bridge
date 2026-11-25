package app.byteland.ghidra.adapter.ghidra;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.adapter.ghidra.GhidraTestSupport.ProgramHolder;
import app.byteland.ghidra.adapter.ghidra.function.FunctionServiceImpl;
import app.byteland.ghidra.adapter.ghidra.symbol.SymbolServiceImpl;
import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.ScanProgress;
import app.byteland.ghidra.service.decompilation.DecompilationResource;
import app.byteland.ghidra.service.function.FunctionCallResource;
import app.byteland.ghidra.service.function.FunctionResource;
import app.byteland.ghidra.service.function.FunctionService.FunctionQuery;
import app.byteland.ghidra.service.symbol.SymbolResource;
import app.byteland.ghidra.service.symbol.SymbolService.DemangleResult;
import app.byteland.ghidra.service.symbol.SymbolService.SymbolQuery;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.DefaultAddressFactory;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.task.TaskMonitor;
import java.io.ByteArrayInputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class CppSymbolIndexTest {
  private static final AddressScanOptions UNBOUNDED_SCAN =
      AddressScanOptions.of(null, null, AddressScanOptions.MAX_TIMEOUT_MS);

  @BeforeAll
  static void initDemanglers() {
    GhidraTestSupport.ensureDemanglersInitialized();
  }

  @Test
  void prewarmedSessionServesAllReadPathsWithZeroDemanglerCallsAndWithoutMutatingProgram()
      throws Exception {
    try (ProgramHolder holder = GhidraTestSupport.createX64Program("cpp_prewarm_reads")) {
      AtomicReference<Address> callerEntry = new AtomicReference<>();
      AtomicReference<Address> calleeEntry = new AtomicReference<>();
      AtomicReference<Long> extSymbolId = new AtomicReference<>();
      holder.inTransaction(
          program -> {
            program.setExecutableFormat("Executable and Linking Format (ELF)");
            Address base = initCodeBlock(program, 0x100000L, 0x1000);
            FunctionManager fm = program.getFunctionManager();
            SymbolTable st = program.getSymbolTable();

            Function caller = createRetFunction(fm, "_ZN4core6Engine3runEi", base);
            Function callee = createRetFunction(fm, "_ZN4core6Logger4infoEPKc", base.add(0x20));
            createRetFunction(fm, "__ZN4core6Helper4initEv", base.add(0x40));
            createRetFunction(fm, "plain_c_helper", base.add(0x60));
            st.createLabel(base.add(0x80), "_Z999not_valid_itanium$$$", SourceType.IMPORTED);

            program
                .getReferenceManager()
                .addMemoryReference(
                    caller.getEntryPoint(),
                    callee.getEntryPoint(),
                    RefType.UNCONDITIONAL_CALL,
                    SourceType.DEFAULT,
                    0);
            ExternalLocation ext =
                program
                    .getExternalManager()
                    .addExtFunction("libstdc++.so.6", "_ZNSolsEi", null, SourceType.IMPORTED);
            assertNotNull(ext);

            callerEntry.set(caller.getEntryPoint());
            calleeEntry.set(callee.getEntryPoint());
            extSymbolId.set(ext.getSymbol().getID());
          });

      String expectedCallerSignature =
          CppSymbolNames.decodeWith(
                  DemanglerUtil::demangle,
                  holder.program(),
                  "_ZN4core6Engine3runEi",
                  callerEntry.get())
              .signature();
      String expectedHelperSignature =
          CppSymbolNames.decodeWith(
                  DemanglerUtil::demangle, holder.program(), "__ZN4core6Helper4initEv", null)
              .signature();
      assertNotNull(expectedCallerSignature);

      long initialModNumber = holder.program().getModificationNumber();
      AtomicInteger rawDemangleCalls = new AtomicInteger();
      AtomicBoolean heldLockDuringDemangle = new AtomicBoolean(false);
      AtomicReference<GhidraSession> sessionRef = new AtomicReference<>();

      CppDemangler countingDemangler =
          (program, name, address) -> {
            GhidraSession current = sessionRef.get();
            if (current != null && current.holdsExecutionLock()) {
              heldLockDuringDemangle.set(true);
            }
            rawDemangleCalls.incrementAndGet();
            return DemanglerUtil.demangle(program, name, address);
          };

      GhidraScript script = GhidraTestSupport.scriptFor(holder.program());
      GhidraSession session =
          new GhidraSession(script, CppSymbolIndexConfig.defaults(), countingDemangler);
      sessionRef.set(session);
      try (BridgeServices services = GhidraServiceFactory.create(session)) {
        assertTrue(session.cppSymbols().awaitPrewarm(Duration.ofSeconds(10)));
        assertFalse(heldLockDuringDemangle.get());
        assertEquals(initialModNumber, holder.program().getModificationNumber());

        int callsAfterPrewarm = rawDemangleCalls.get();
        assertEquals(5, callsAfterPrewarm);
        assertEquals(0L, session.cppSymbols().hits());
        assertEquals(0L, session.cppSymbols().misses());

        // Run initial and repeat sweeps across function.list, symbol.list, callers, callees, and get.
        for (int sweep = 0; sweep < 3; sweep++) {
          Page<FunctionResource> functions =
              services
                  .functionService()
                  .listFunctions(
                      new FunctionQuery(
                          UNBOUNDED_SCAN,
                          100,
                          null,
                          null,
                          null,
                          null,
                          null,
                          null,
                          Set.of()));
          Map<String, String> fnDemangled = new LinkedHashMap<>();
          for (FunctionResource fn : functions.items()) {
            fnDemangled.put(fn.name(), fn.demangledName());
          }
          assertEquals(expectedCallerSignature, fnDemangled.get("_ZN4core6Engine3runEi"));
          assertEquals(
              expectedCallerSignature,
              CppSymbolNames.demangled(
                  holder.program(), "_ZN4core6Engine3runEi", callerEntry.get()));
          assertNotNull(fnDemangled.get("_ZN4core6Logger4infoEPKc"));
          assertEquals(expectedHelperSignature, fnDemangled.get("__ZN4core6Helper4initEv"));
          assertNull(fnDemangled.get("plain_c_helper"));

          Page<SymbolResource> symbols =
              services
                  .symbolService()
                  .listSymbols(
                      new SymbolQuery(
                          UNBOUNDED_SCAN,
                          null,
                          null,
                          null,
                          null,
                          null,
                          true,
                          100,
                          null));
          Map<String, String> symDemangled = new LinkedHashMap<>();
          for (SymbolResource sym : symbols.items()) {
            symDemangled.put(sym.name(), sym.demangledName());
          }
          assertEquals(
              fnDemangled.get("_ZN4core6Engine3runEi"),
              symDemangled.get("_ZN4core6Engine3runEi"));
          assertNotNull(services.symbolService().getSymbol(extSymbolId.get()).demangledName());
          assertNull(symDemangled.get("_Z999not_valid_itanium$$$"));
          assertNull(symDemangled.get("plain_c_helper"));

          Page<FunctionCallResource> callees =
              services
                  .functionService()
                  .getCallees(AddressUtil.canonicalAddress(callerEntry.get()), 10, null);
          assertEquals(1, callees.items().size());
          assertEquals(
              fnDemangled.get("_ZN4core6Logger4infoEPKc"),
              callees.items().getFirst().demangledName());

          Page<FunctionCallResource> callers =
              services
                  .functionService()
                  .getCallers(AddressUtil.canonicalAddress(calleeEntry.get()), 10, null);
          assertEquals(1, callers.items().size());
          assertEquals(
              fnDemangled.get("_ZN4core6Engine3runEi"),
              callers.items().getFirst().demangledName());

          DecompilationResource doc =
              services
                  .decompilationService()
                  .decompileFunction(
                      AddressUtil.canonicalAddress(callerEntry.get()),
                      DecompilationResource.Format.DOCUMENT,
                      5_000,
                      false);
          assertTrue(doc.completed());
          boolean sawIndexedFuncToken =
              doc.lines().stream()
                  .flatMap(line -> line.tokens().stream())
                  .map(DecompilationResource.LocatedToken::symbol)
                  .filter(sym -> sym != null && "_ZN4core6Engine3runEi".equals(sym.name()))
                  .anyMatch(
                      sym ->
                          fnDemangled
                              .get("_ZN4core6Engine3runEi")
                              .equals(sym.demangledName()));
          assertTrue(sawIndexedFuncToken);
        }

        // Zero DemanglerUtil.demangle calls occurred after pre-warming completed.
        assertEquals(callsAfterPrewarm, rawDemangleCalls.get());
        assertEquals(0L, session.cppSymbols().misses());
        assertTrue(session.cppSymbols().hits() > 0L);
        assertEquals(initialModNumber, holder.program().getModificationNumber());
      } finally {
        endAmbientTransaction(script);
      }
    }
  }

  @Test
  void servesConcurrentOnDemandQueriesDuringPrewarmWithoutWaitingForFullCompletion()
      throws Exception {
    try (ProgramHolder holder = GhidraTestSupport.createX64Program("cpp_concurrent_on_demand")) {
      Address[] lateAddress = new Address[1];
      String blockedName = "_ZN5alpha10blocked_fnEv";
      String lateName = "_ZN5omega9target_fnEi";

      holder.inTransaction(
          program -> {
            program.setExecutableFormat("Executable and Linking Format (ELF)");
            Address base = initCodeBlock(program, 0x200000L, 0x2000);
            FunctionManager fm = program.getFunctionManager();
            createRetFunction(fm, blockedName, base);
            for (int i = 0; i < 25; i++) {
              createRetFunction(fm, "_ZN6middle6item" + (10 + i) + "Ev", base.add(0x20L * (i + 1)));
            }
            Function lateFn = createRetFunction(fm, lateName, base.add(0x800));
            lateAddress[0] = lateFn.getEntryPoint();
          });

      String expectedLateDemangled =
          CppSymbolNames.decodeWith(
                  DemanglerUtil::demangle, holder.program(), lateName, lateAddress[0])
              .signature();
      assertNotNull(expectedLateDemangled);

      CountDownLatch enteredBlockedSymbol = new CountDownLatch(1);
      CountDownLatch releaseBlockedSymbol = new CountDownLatch(1);
      ConcurrentHashMap<String, AtomicInteger> perSymbolCalls = new ConcurrentHashMap<>();

      CppDemangler controlledDemangler =
          (program, name, address) -> {
            perSymbolCalls.computeIfAbsent(name, ignored -> new AtomicInteger()).incrementAndGet();
            if (blockedName.equals(name)) {
              enteredBlockedSymbol.countDown();
              try {
                assertTrue(releaseBlockedSymbol.await(10, TimeUnit.SECONDS));
              } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
              }
            }
            return DemanglerUtil.demangle(program, name, address);
          };

      GhidraScript script = GhidraTestSupport.scriptFor(holder.program());
      GhidraSession session =
          new GhidraSession(
              script, new CppSymbolIndexConfig(1024, 8L * 1024 * 1024, 4), controlledDemangler);
      try (BridgeServices services = GhidraServiceFactory.create(session)) {
        // Wait until background pre-warming is paused inside the first symbol.
        assertTrue(enteredBlockedSymbol.await(5, TimeUnit.SECONDS));
        assertTrue(session.cppSymbols().isPrewarming());

        // Query the late symbol on demand while pre-warming is blocked on the first symbol.
        FunctionResource resolvedDuringPrewarm =
            services
                .functionService()
                .getFunction(AddressUtil.canonicalAddress(lateAddress[0]), Set.of());
        assertEquals(expectedLateDemangled, resolvedDuringPrewarm.demangledName());

        // Unblock pre-warming and verify full completion does not decode the late symbol again.
        releaseBlockedSymbol.countDown();
        assertTrue(session.cppSymbols().awaitPrewarm(Duration.ofSeconds(10)));
        assertEquals(1, perSymbolCalls.get(lateName).get());
      } finally {
        releaseBlockedSymbol.countDown();
        endAmbientTransaction(script);
      }
    }
  }

  @Test
  void programMutationsKeepUnchangedEntriesAndDecodeOnlyNewlyAddedMangledNames() throws Exception {
    try (ProgramHolder holder = GhidraTestSupport.createX64Program("cpp_mutation_delta")) {
      String fnOne = "_ZN3svc5Alpha5startEv";
      String fnTwo = "_ZN3svc4Beta4stopEv";
      String fnThree = "_ZN3svc5Gamma6reloadEi";
      Address[] baseHolder = new Address[1];

      holder.inTransaction(
          program -> {
            program.setExecutableFormat("Executable and Linking Format (ELF)");
            Address base = initCodeBlock(program, 0x300000L, 0x1000);
            baseHolder[0] = base;
            FunctionManager fm = program.getFunctionManager();
            createRetFunction(fm, fnOne, base);
            createRetFunction(fm, fnTwo, base.add(0x20));
          });

      ConcurrentHashMap<String, AtomicInteger> perSymbolCalls = new ConcurrentHashMap<>();
      CppDemangler trackingDemangler =
          (program, name, address) -> {
            perSymbolCalls.computeIfAbsent(name, ignored -> new AtomicInteger()).incrementAndGet();
            return DemanglerUtil.demangle(program, name, address);
          };

      GhidraScript script = GhidraTestSupport.scriptFor(holder.program());
      try (GhidraSession session =
          new GhidraSession(script, CppSymbolIndexConfig.defaults(), trackingDemangler)) {
        FunctionServiceImpl functionService = new FunctionServiceImpl(session);
        SymbolServiceImpl symbolService = new SymbolServiceImpl(session);
        session.startCppSymbolPrewarm();
        assertTrue(session.cppSymbols().awaitPrewarm(Duration.ofSeconds(10)));

        assertEquals(1, perSymbolCalls.get(fnOne).get());
        assertEquals(1, perSymbolCalls.get(fnTwo).get());

        // Mutate the program in a session transaction: add one plain label and one mangled function.
        session.withTransaction(
            () -> {
              ProgramDB program = holder.program();
              program
                  .getSymbolTable()
                  .createLabel(baseHolder[0].add(0x100), "plain_added", SourceType.USER_DEFINED);
              createRetFunction(program.getFunctionManager(), fnThree, baseHolder[0].add(0x40));
              return null;
            });

        assertTrue(session.cppSymbols().awaitPrewarm(Duration.ofSeconds(10)));

        Page<FunctionResource> functions =
            functionService.listFunctions(
                new FunctionQuery(
                    UNBOUNDED_SCAN, 50, null, null, null, null, null, null, Set.of()));
        Map<String, String> names = new LinkedHashMap<>();
        for (FunctionResource fn : functions.items()) {
          names.put(fn.name(), fn.demangledName());
        }
        assertNotNull(names.get(fnOne));
        assertNotNull(names.get(fnTwo));
        assertNotNull(names.get(fnThree));

        Page<SymbolResource> symbols =
            symbolService.listSymbols(
                new SymbolQuery(
                    UNBOUNDED_SCAN,
                    null,
                    null,
                    null,
                    null,
                    null,
                    true,
                    50,
                    null));
        assertFalse(symbols.items().isEmpty());

        // Unchanged mangled names were not decoded again; only the added mangled name was decoded.
        assertEquals(1, perSymbolCalls.get(fnOne).get());
        assertEquals(1, perSymbolCalls.get(fnTwo).get());
        assertEquals(1, perSymbolCalls.get(fnThree).get());

        // Mutate directly on ProgramDB outside GhidraSession.withTransaction to simulate GUI edits.
        String fnFour = "_ZN3svc5Delta5flushEv";
        holder.inTransaction(
            program -> {
              program
                  .getSymbolTable()
                  .createLabel(baseHolder[0].add(0x120), "gui_plain_label", SourceType.USER_DEFINED);
              createRetFunction(program.getFunctionManager(), fnFour, baseHolder[0].add(0x60));
            });

        assertTrue(session.cppSymbols().awaitPrewarm(Duration.ofSeconds(10)));
        assertEquals(1, perSymbolCalls.get(fnOne).get());
        assertEquals(1, perSymbolCalls.get(fnTwo).get());
        assertEquals(1, perSymbolCalls.get(fnThree).get());
        assertEquals(1, perSymbolCalls.get(fnFour).get());

        Page<SymbolResource> refreshedSymbols =
            symbolService.listSymbols(
                new SymbolQuery(
                    UNBOUNDED_SCAN,
                    null,
                    null,
                    null,
                    null,
                    null,
                    true,
                    50,
                    null));
        Map<String, String> refreshedByName = new LinkedHashMap<>();
        for (SymbolResource sym : refreshedSymbols.items()) {
          refreshedByName.put(sym.name(), sym.demangledName());
        }
        assertTrue(refreshedByName.containsKey("gui_plain_label"));
        assertNull(refreshedByName.get("gui_plain_label"));
        assertNotNull(refreshedByName.get(fnFour));
      } finally {
        endAmbientTransaction(script);
      }
    }
  }

  @Test
  void symbolDemangleAndFollowupSweepsReuseIndexedMetadataWithIdenticalDemangleResult()
      throws Exception {
    try (ProgramHolder indexedHolder = GhidraTestSupport.createX64Program("cpp_demangle_indexed");
        ProgramHolder baselineHolder =
            GhidraTestSupport.createX64Program("cpp_demangle_baseline")) {
      populateBatchDemangleFixture(indexedHolder);
      populateBatchDemangleFixture(baselineHolder);

      // Run baseline unindexed demangle and symbol.list sweep.
      GhidraScript baselineScript = GhidraTestSupport.scriptFor(baselineHolder.program());
      DemangleResult baselineResult;
      List<String> baselineSymbolSummary;
      try (GhidraSession baselineSession = new GhidraSession(baselineScript)) {
        SymbolServiceImpl baselineSymbols = new SymbolServiceImpl(baselineSession);
        baselineResult = baselineSymbols.demangleSymbols();
        baselineSymbolSummary = summarizeSymbols(baselineSymbols);
      } finally {
        endAmbientTransaction(baselineScript);
      }

      // Run pre-warmed session demangle and follow-up sweeps and verify zero extra demangle calls.
      AtomicInteger demangleCalls = new AtomicInteger();
      CppDemangler countingDemangler =
          (program, name, address) -> {
            demangleCalls.incrementAndGet();
            return DemanglerUtil.demangle(program, name, address);
          };

      GhidraScript indexedScript = GhidraTestSupport.scriptFor(indexedHolder.program());
      GhidraSession indexedSession =
          new GhidraSession(indexedScript, CppSymbolIndexConfig.defaults(), countingDemangler);
      try (BridgeServices services = GhidraServiceFactory.create(indexedSession)) {
        assertTrue(indexedSession.cppSymbols().awaitPrewarm(Duration.ofSeconds(10)));

        int callsAfterPrewarm = demangleCalls.get();
        assertEquals(4, callsAfterPrewarm);

        DemangleResult indexedResult = services.symbolService().demangleSymbols();
        assertEquals(baselineResult, indexedResult);
        assertEquals(3, indexedResult.renamed());
        assertEquals(1, indexedResult.failed());

        // Run follow-up symbol.list and function.list refreshes after symbol.demangle.
        List<String> indexedSymbolSummary = summarizeSymbols(services.symbolService());
        List<String> repeatSymbolSummary = summarizeSymbols(services.symbolService());
        services
            .functionService()
            .listFunctions(
                new FunctionQuery(
                    UNBOUNDED_SCAN, 50, null, null, null, null, null, null, Set.of()));

        assertEquals(baselineSymbolSummary, indexedSymbolSummary);
        assertEquals(baselineSymbolSummary, repeatSymbolSummary);
        assertEquals(callsAfterPrewarm, demangleCalls.get());
      } finally {
        endAmbientTransaction(indexedScript);
      }
    }
  }

  @Test
  void pausesPrewarmDuringTransactionsAndAnalysisAndResumesAfterward() throws Exception {
    try (ProgramHolder holder = GhidraTestSupport.createX64Program("cpp_pause_tx_analysis")) {
      holder.inTransaction(
          program -> {
            program.setExecutableFormat("Executable and Linking Format (ELF)");
            Address base = initCodeBlock(program, 0x400000L, 0x1000);
            FunctionManager fm = program.getFunctionManager();
            for (int i = 0; i < 16; i++) {
              createRetFunction(fm, "_ZN5pause8worker" + (10 + i) + "Ev", base.add(0x20L * i));
            }
          });

      CountDownLatch firstBatchStarted = new CountDownLatch(1);
      CountDownLatch finishFirstSymbol = new CountDownLatch(1);
      AtomicInteger callsDuringPauseWindow = new AtomicInteger();
      AtomicBoolean pauseWindowOpen = new AtomicBoolean(false);
      AtomicBoolean lockHeldDuringDemangle = new AtomicBoolean(false);
      AtomicReference<GhidraSession> sessionRef = new AtomicReference<>();

      CppDemangler demangler =
          (program, name, address) -> {
            GhidraSession current = sessionRef.get();
            if (current != null && current.holdsExecutionLock()) {
              lockHeldDuringDemangle.set(true);
            }
            if (pauseWindowOpen.get()) {
              callsDuringPauseWindow.incrementAndGet();
            }
            if (firstBatchStarted.getCount() > 0) {
              firstBatchStarted.countDown();
              try {
                assertTrue(finishFirstSymbol.await(10, TimeUnit.SECONDS));
              } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
              }
            }
            return DemanglerUtil.demangle(program, name, address);
          };

      GhidraScript script = GhidraTestSupport.scriptFor(holder.program());
      try (GhidraSession session =
          new GhidraSession(
              script, new CppSymbolIndexConfig(1024, 8L * 1024 * 1024, 2), demangler)) {
        sessionRef.set(session);
        session.startCppSymbolPrewarm();
        assertTrue(firstBatchStarted.await(5, TimeUnit.SECONDS));
        assertFalse(lockHeldDuringDemangle.get());

        // Start simulated bridge analysis while releasing the first symbol decode.
        session.onAnalysisStarted();
        try {
          finishFirstSymbol.countDown();
          Thread.sleep(60L);
          pauseWindowOpen.set(true);
          Thread.sleep(80L);
          assertEquals(0, callsDuringPauseWindow.get());
        } finally {
          pauseWindowOpen.set(false);
          session.onAnalysisFinished();
        }

        // Verify withTransaction acquires executionLock immediately and pauses pre-warming.
        ExecutorService txRunner = Executors.newSingleThreadExecutor();
        try {
          CountDownLatch insideTx = new CountDownLatch(1);
          CountDownLatch releaseTx = new CountDownLatch(1);
          Future<?> txFuture =
              txRunner.submit(
                  () ->
                      session.withTransaction(
                          () -> {
                            insideTx.countDown();
                            releaseTx.await(5, TimeUnit.SECONDS);
                            return null;
                          }));
          assertTrue(insideTx.await(5, TimeUnit.SECONDS));
          releaseTx.countDown();
          txFuture.get(5, TimeUnit.SECONDS);
        } finally {
          txRunner.shutdownNow();
        }

        assertTrue(session.cppSymbols().awaitPrewarm(Duration.ofSeconds(10)));
        assertEquals(16, session.cppSymbols().entryCount());
        assertFalse(lockHeldDuringDemangle.get());
      } finally {
        finishFirstSymbol.countDown();
        endAmbientTransaction(script);
      }
    }
  }

  @Test
  void capsIndexedEntriesAndBytesWithConfigurableBoundsWithoutPrewarmThrashing() throws Exception {
    try (ProgramHolder holder = GhidraTestSupport.createX64Program("cpp_memory_bound")) {
      List<String> names = new ArrayList<>();
      holder.inTransaction(
          program -> {
            program.setExecutableFormat("Executable and Linking Format (ELF)");
            Address base = initCodeBlock(program, 0x500000L, 0x1000);
            FunctionManager fm = program.getFunctionManager();
            for (int i = 0; i < 12; i++) {
              String mangled = "_ZN7bounded9service" + (10 + i) + "Ei";
              names.add(mangled);
              createRetFunction(fm, mangled, base.add(0x20L * i));
            }
          });

      AtomicInteger demangleCalls = new AtomicInteger();
      CppDemangler countingDemangler =
          (program, name, address) -> {
            demangleCalls.incrementAndGet();
            return DemanglerUtil.demangle(program, name, address);
          };

      long maxBytes = 1_800L;
      int maxEntries = 4;
      GhidraScript script = GhidraTestSupport.scriptFor(holder.program());
      try (GhidraSession session =
          new GhidraSession(
              script,
              new CppSymbolIndexConfig(maxEntries, maxBytes, 2),
              countingDemangler)) {
        session.startCppSymbolPrewarm();
        assertTrue(session.cppSymbols().awaitPrewarm(Duration.ofSeconds(10)));

        // Pre-warming stops at the entry or byte cap instead of thrashing through all 12 symbols.
        assertTrue(session.cppSymbols().entryCount() <= maxEntries);
        assertTrue(session.cppSymbols().estimatedBytes() <= maxBytes);
        assertTrue(demangleCalls.get() <= maxEntries + 1);

        // Foreground lookups for uncached symbols succeed and respect both bounds via LRU eviction.
        Address base =
            holder.program().getAddressFactory().getDefaultAddressSpace().getAddress(0x500000L);
        for (int i = 0; i < names.size(); i++) {
          String resolved =
              session.cppSymbols().demangled(holder.program(), names.get(i), base.add(0x20L * i));
          assertNotNull(resolved);
          assertTrue(session.cppSymbols().entryCount() <= maxEntries);
          assertTrue(session.cppSymbols().estimatedBytes() <= maxBytes);
        }
      } finally {
        endAmbientTransaction(script);
      }
    }
  }

  @Test
  void bridgeServicesCloseCancelsActivePrewarmingAndReleasesAllIndexMemory() throws Exception {
    try (ProgramHolder holder = GhidraTestSupport.createX64Program("cpp_close_releases")) {
      holder.inTransaction(
          program -> {
            program.setExecutableFormat("Executable and Linking Format (ELF)");
            Address base = initCodeBlock(program, 0x600000L, 0x1000);
            FunctionManager fm = program.getFunctionManager();
            for (int i = 0; i < 20; i++) {
              createRetFunction(fm, "_ZN8shutdown6task" + (10 + i) + "Ev", base.add(0x20L * i));
            }
          });

      CountDownLatch fifthSymbolEntered = new CountDownLatch(1);
      CountDownLatch interruptedLatch = new CountDownLatch(1);
      AtomicInteger seenCount = new AtomicInteger();

      CppDemangler blockingDemangler =
          (program, name, address) -> {
            int index = seenCount.incrementAndGet();
            if (index == 5) {
              fifthSymbolEntered.countDown();
              try {
                Thread.sleep(60_000L);
              } catch (InterruptedException interrupted) {
                interruptedLatch.countDown();
                Thread.currentThread().interrupt();
                return List.of();
              }
            }
            return DemanglerUtil.demangle(program, name, address);
          };

      GhidraScript script = GhidraTestSupport.scriptFor(holder.program());
      GhidraSession session =
          new GhidraSession(
              script,
              new CppSymbolIndexConfig(1024, 8L * 1024 * 1024, 4),
              blockingDemangler);
      BridgeServices services = GhidraServiceFactory.create(session);

      assertTrue(fifthSymbolEntered.await(5, TimeUnit.SECONDS));
      assertEquals(4, session.cppSymbols().entryCount());
      assertTrue(session.cppSymbols().estimatedBytes() > 0L);
      assertTrue(session.cppSymbols().isPrewarming());

      services.close();

      assertTrue(interruptedLatch.await(5, TimeUnit.SECONDS));
      assertTrue(session.cppSymbols().isClosed());
      assertFalse(session.cppSymbols().isPrewarming());
      assertEquals(0, session.cppSymbols().entryCount());
      assertEquals(0L, session.cppSymbols().estimatedBytes());
      endAmbientTransaction(script);
    }
  }

  @Test
  void prewarmedSymbolSnapshotMatchesLiveSymbolScanAcrossFiltersCursorsAndBatchBoundaries()
      throws Exception {
    try (ProgramHolder holder = GhidraTestSupport.createX64Program("cpp_snapshot_parity")) {
      Address[] sharedAddrHolder = new Address[1];
      Address[] rangeStartHolder = new Address[1];
      Address[] rangeEndHolder = new Address[1];

      holder.inTransaction(
          program -> {
            program.setExecutableFormat("Executable and Linking Format (ELF)");
            Address base = initCodeBlock(program, 0x800000L, 0x1000);
            FunctionManager fm = program.getFunctionManager();
            SymbolTable st = program.getSymbolTable();

            Namespace outerNs = st.createNameSpace(null, "engine", SourceType.USER_DEFINED);
            Namespace innerNs = st.createNameSpace(outerNs, "audio", SourceType.USER_DEFINED);

            createRetFunction(fm, "_ZN6engine5Mixer4initEv", base);
            Address sharedAddr = base.add(0x20);
            sharedAddrHolder[0] = sharedAddr;
            createRetFunction(fm, "_ZN6engine5Mixer3mixEPf", sharedAddr);
            st.createLabel(sharedAddr, "mixer_secondary_alias", innerNs, SourceType.USER_DEFINED);
            st.createLabel(sharedAddr, "_ZN6engine5Mixer9alias_symEv", outerNs, SourceType.IMPORTED);

            rangeStartHolder[0] = base.add(0x20);
            rangeEndHolder[0] = base.add(0x60);

            st.createLabel(base.add(0x40), "PlainGlobalTag", SourceType.ANALYSIS);
            createRetFunction(fm, "_ZN6engine5Codec6decodeEPKh", base.add(0x60));
            st.createLabel(base.add(0x80), "tail_marker", innerNs, SourceType.USER_DEFINED);
          });

      GhidraScript prewarmedScript = GhidraTestSupport.scriptFor(holder.program());
      GhidraScript liveScript = GhidraTestSupport.scriptFor(holder.program());
      try (GhidraSession prewarmedSession =
              new GhidraSession(
                  prewarmedScript,
                  new CppSymbolIndexConfig(1024, 8L * 1024 * 1024, 2),
                  DemanglerUtil::demangle);
          GhidraSession liveSession =
              new GhidraSession(
                  liveScript,
                  new CppSymbolIndexConfig(1024, 8L * 1024 * 1024, 2),
                  DemanglerUtil::demangle)) {
        prewarmedSession.startCppSymbolPrewarm();
        assertTrue(prewarmedSession.cppSymbols().awaitPrewarm(Duration.ofSeconds(10)));
        assertNotNull(
            prewarmedSession
                .cppSymbols()
                .symbolSnapshotIfCurrent(holder.program(), holder.program().getMinAddress()));
        assertNull(
            liveSession
                .cppSymbols()
                .symbolSnapshotIfCurrent(holder.program(), holder.program().getMinAddress()));

        SymbolServiceImpl snapshotService = new SymbolServiceImpl(prewarmedSession);
        SymbolServiceImpl liveService = new SymbolServiceImpl(liveSession);

        List<SymbolQuery> queries =
            List.of(
                new SymbolQuery(UNBOUNDED_SCAN, null, null, null, null, null, true, 100, null),
                new SymbolQuery(UNBOUNDED_SCAN, null, null, null, null, null, true, 2, null),
                new SymbolQuery(
                    UNBOUNDED_SCAN, null, null, "Function", null, null, true, 10, null),
                new SymbolQuery(
                    UNBOUNDED_SCAN, null, null, "Label", "engine::audio", null, true, 10, null),
                new SymbolQuery(
                    UNBOUNDED_SCAN, null, null, null, null, "USER_DEFINED", true, 10, null),
                new SymbolQuery(UNBOUNDED_SCAN, "Mixer", null, null, null, null, true, 10, null),
                new SymbolQuery(UNBOUNDED_SCAN, "mixer", null, null, null, null, true, 10, null),
                new SymbolQuery(UNBOUNDED_SCAN, "mixer", null, null, null, null, false, 10, null),
                new SymbolQuery(
                    UNBOUNDED_SCAN,
                    null,
                    AddressUtil.canonicalAddress(sharedAddrHolder[0]),
                    null,
                    null,
                    null,
                    true,
                    1,
                    null),
                new SymbolQuery(
                    AddressScanOptions.of(
                        AddressUtil.canonicalAddress(rangeStartHolder[0]),
                        AddressUtil.canonicalAddress(rangeEndHolder[0]),
                        AddressScanOptions.MAX_TIMEOUT_MS),
                    null,
                    null,
                    null,
                    null,
                    null,
                    true,
                    2,
                    null));

        for (SymbolQuery initialQuery : queries) {
          assertPaginatedParity(liveService, snapshotService, initialQuery);
        }
      } finally {
        endAmbientTransaction(prewarmedScript);
        endAmbientTransaction(liveScript);
      }
    }
  }

  @Test
  void sharesStaticCppSymbolNamesCacheWithDefaultSessionAndUnbindsOnClose() throws Exception {
    try (ProgramHolder holder = GhidraTestSupport.createX64Program("cpp_static_share")) {
      String prewarmedByStatic = "_ZN6shared5Cache4seedEi";
      String sessionOnly = "_ZN6shared5Cache5extraEv";
      Address[] baseHolder = new Address[1];

      holder.inTransaction(
          program -> {
            program.setExecutableFormat("Executable and Linking Format (ELF)");
            Address base = initCodeBlock(program, 0x900000L, 0x1000);
            baseHolder[0] = base;
            FunctionManager fm = program.getFunctionManager();
            createRetFunction(fm, prewarmedByStatic, base);
            createRetFunction(fm, sessionOnly, base.add(0x20));
          });

      // Warm one symbol in CppSymbolNames static cache before opening a session.
      String expectedSeed =
          CppSymbolNames.demangled(holder.program(), prewarmedByStatic, baseHolder[0]);
      assertNotNull(expectedSeed);

      GhidraScript script = GhidraTestSupport.scriptFor(holder.program());
      GhidraSession session = new GhidraSession(script);
      BridgeServices services = GhidraServiceFactory.create(session);
      try {
        assertTrue(session.cppSymbols().awaitPrewarm(Duration.ofSeconds(10)));
        // Pre-warmer imported prewarmedByStatic from static cache and only decoded sessionOnly.
        assertEquals(1L, session.cppSymbols().demangleCalls());
        assertEquals(2, session.cppSymbols().entryCount());

        // CppSymbolNames.demangled delegates to the bound session index while active.
        long hitsBefore = session.cppSymbols().hits();
        assertEquals(
            expectedSeed,
            CppSymbolNames.demangled(holder.program(), prewarmedByStatic, baseHolder[0]));
        assertNotNull(
            CppSymbolNames.demangled(holder.program(), sessionOnly, baseHolder[0].add(0x20)));
        assertEquals(hitsBefore + 2L, session.cppSymbols().hits());
      } finally {
        services.close();
        endAmbientTransaction(script);
      }

      assertTrue(session.cppSymbols().isClosed());
      assertNull(CppSymbolNames.sessionIndexFor(holder.program()));
      assertEquals(
          expectedSeed,
          CppSymbolNames.demangled(holder.program(), prewarmedByStatic, baseHolder[0]));
    }
  }

  @Test
  void resetsIndexOnProgramSwitchAndSupportsStrictProxyPrograms() throws Exception {
    GenericAddressSpace ram = new GenericAddressSpace("ram", 64, AddressSpace.TYPE_RAM, 0);
    AddressFactory factory = new DefaultAddressFactory(new AddressSpace[] {ram});
    Program strictProxy =
        (Program)
            Proxy.newProxyInstance(
                Program.class.getClassLoader(),
                new Class<?>[] {Program.class},
                (proxy, method, args) -> {
                  if ("getAddressFactory".equals(method.getName())) {
                    return factory;
                  }
                  throw new AssertionError("Unexpected proxy call: " + method.getName());
                });
    GhidraScript strictScript =
        new GhidraScript() {
          {
            this.monitor =
                (TaskMonitor)
                    Proxy.newProxyInstance(
                        TaskMonitor.class.getClassLoader(),
                        new Class<?>[] {TaskMonitor.class},
                        (proxy, method, args) -> {
                          throw new AssertionError("Read touched monitor: " + method.getName());
                        });
          }

          @Override
          protected void run() {}

          @Override
          public Program getCurrentProgram() {
            return strictProxy;
          }
        };

    try (GhidraSession strictSession = new GhidraSession(strictScript)) {
      assertFalse(strictSession.canCacheSnapshots());
      strictSession.startCppSymbolPrewarm();
      assertTrue(strictSession.cppSymbols().awaitPrewarm(Duration.ofSeconds(2)));
      assertNull(strictSession.cppSymbols().demangled(strictProxy, "plain_symbol", null));
    }

    try (ProgramHolder first = GhidraTestSupport.createX64Program("cpp_switch_one");
        ProgramHolder second = GhidraTestSupport.createX64Program("cpp_switch_two")) {
      first.inTransaction(
          program -> {
            program.setExecutableFormat("Executable and Linking Format (ELF)");
            Address base = initCodeBlock(program, 0x100000L, 0x100);
            createRetFunction(program.getFunctionManager(), "_ZN6switch3One3runEv", base);
          });
      second.inTransaction(
          program -> {
            program.setExecutableFormat("Executable and Linking Format (ELF)");
            Address base = initCodeBlock(program, 0x200000L, 0x100);
            createRetFunction(program.getFunctionManager(), "_ZN6switch3Two3runEv", base);
          });

      AtomicReference<Program> activeProgram = new AtomicReference<>(first.program());
      GhidraScript switchingScript =
          new GhidraScript() {
            {
              set(first.program(), TaskMonitor.DUMMY);
            }

            @Override
            protected void run() {}

            @Override
            public Program getCurrentProgram() {
              return activeProgram.get();
            }
          };

      try (GhidraSession session = new GhidraSession(switchingScript)) {
        session.startCppSymbolPrewarm();
        assertTrue(session.cppSymbols().awaitPrewarm(Duration.ofSeconds(10)));
        assertEquals(1, session.cppSymbols().entryCount());
        assertEquals(session.cppSymbols(), CppSymbolNames.sessionIndexFor(first.program()));

        activeProgram.set(second.program());
        assertTrue(session.cppSymbols().awaitPrewarm(Duration.ofSeconds(10)));
        assertNull(CppSymbolNames.sessionIndexFor(first.program()));
        assertEquals(session.cppSymbols(), CppSymbolNames.sessionIndexFor(second.program()));
        assertEquals(1, session.cppSymbols().entryCount());
        assertNotNull(
            CppSymbolNames.demangled(second.program(), "_ZN6switch3Two3runEv", null));
      } finally {
        endAmbientTransaction(switchingScript);
      }
    }
  }

  @Test
  void canonicalAddressFastPathMatchesLegacyFormattingAcrossSpacesAndBoundaries() throws Exception {
    GenericAddressSpace space8 =
        new GenericAddressSpace("mem8", 8, AddressSpace.TYPE_RAM, 0);
    GenericAddressSpace space16 =
        new GenericAddressSpace("mem16", 16, AddressSpace.TYPE_RAM, 1);
    GenericAddressSpace space32 =
        new GenericAddressSpace("ram", 32, AddressSpace.TYPE_RAM, 2);
    GenericAddressSpace space48 =
        new GenericAddressSpace("mem48", 48, AddressSpace.TYPE_RAM, 3);
    GenericAddressSpace space64 =
        new GenericAddressSpace("ram64", 64, AddressSpace.TYPE_RAM, 4);
    GenericAddressSpace namedSpace =
        new GenericAddressSpace("OTHER", 64, AddressSpace.TYPE_OTHER, 5);
    namedSpace.setShowSpaceName(true);
    GenericAddressSpace wordSpace =
        new GenericAddressSpace("code16", 16, 2, AddressSpace.TYPE_CODE, 6);

    long[] offsets64 = {
      0L,
      1L,
      0xfL,
      0x10L,
      0xffL,
      0x100L,
      0xfffL,
      0x1000L,
      0xffffL,
      0x10000L,
      0x400000L,
      0x7fffffffL,
      0xffffffffL,
      0x1_0000_0000L,
      0x0001_2345_6789_abcdL,
      Long.MAX_VALUE,
      Long.MIN_VALUE,
      -1L
    };
    for (long offset : offsets64) {
      assertCanonicalMatchesLegacy(space64.getAddress(offset));
      assertCanonicalMatchesLegacy(namedSpace.getAddress(offset));
    }

    long[] offsets32 = {0L, 1L, 0xfL, 0x10L, 0xffffL, 0x400000L, 0xffffffffL};
    for (long offset : offsets32) {
      assertCanonicalMatchesLegacy(space32.getAddress(offset));
      assertCanonicalMatchesLegacy(space48.getAddress(offset));
    }

    for (long offset : new long[] {0L, 1L, 0xfL, 0x10L, 0xffL}) {
      assertCanonicalMatchesLegacy(space8.getAddress(offset));
    }
    for (long offset : new long[] {0L, 1L, 0xfL, 0xffL, 0x1000L, 0xffffL}) {
      assertCanonicalMatchesLegacy(space16.getAddress(offset));
      assertCanonicalMatchesLegacy(wordSpace.getAddress(offset));
    }

    try (ProgramHolder holder = GhidraTestSupport.createX64Program("cpp_addr_fastpath")) {
      Address[] extAddress = new Address[1];
      holder.inTransaction(
          program -> {
            ExternalLocation ext =
                program
                    .getExternalManager()
                    .addExtFunction("libc.so.6", "puts", null, SourceType.IMPORTED);
            extAddress[0] = ext.getExternalSpaceAddress();
          });
      assertCanonicalMatchesLegacy(extAddress[0]);
      assertNull(AddressUtil.canonicalAddress((Address) null));
    }

    // Verify non-GenericAddressSpace fallback delegates without assumptions.
    Address customAddress =
        (Address)
            Proxy.newProxyInstance(
                Address.class.getClassLoader(),
                new Class<?>[] {Address.class},
                (proxy, method, args) -> {
                  if ("getAddressSpace".equals(method.getName())) {
                    return space64;
                  }
                  if ("toString".equals(method.getName()) && (args == null || args.length == 0)) {
                    return "00401000";
                  }
                  try {
                    return method.invoke(space64.getAddress(0x401000L), args);
                  } catch (InvocationTargetException error) {
                    throw error.getTargetException();
                  }
                });
    assertEquals("ram64:00401000", AddressUtil.canonicalAddress(customAddress));
  }

  private static void assertCanonicalMatchesLegacy(Address address) {
    String expected =
        AddressUtil.canonicalAddress(address.getAddressSpace().getName(), address.toString());
    assertEquals(expected, AddressUtil.canonicalAddress(address));
  }

  private static void assertPaginatedParity(
      SymbolServiceImpl liveService,
      SymbolServiceImpl snapshotService,
      SymbolQuery baseQuery) {
    String liveCursor = baseQuery.cursor();
    String snapshotCursor = baseQuery.cursor();
    int pages = 0;
    while (true) {
      SymbolQuery livePageQuery =
          new SymbolQuery(
              baseQuery.scan(),
              baseQuery.name(),
              baseQuery.address(),
              baseQuery.type(),
              baseQuery.namespace(),
              baseQuery.sourceType(),
              baseQuery.caseSensitive(),
              baseQuery.limit(),
              liveCursor);
      SymbolQuery snapshotPageQuery =
          new SymbolQuery(
              baseQuery.scan(),
              baseQuery.name(),
              baseQuery.address(),
              baseQuery.type(),
              baseQuery.namespace(),
              baseQuery.sourceType(),
              baseQuery.caseSensitive(),
              baseQuery.limit(),
              snapshotCursor);
      Page<SymbolResource> livePage = liveService.listSymbols(livePageQuery);
      Page<SymbolResource> snapshotPage = snapshotService.listSymbols(snapshotPageQuery);

      assertEquals(livePage.items(), snapshotPage.items());
      assertEquals(livePage.nextCursor(), snapshotPage.nextCursor());
      ScanProgress liveProgress = livePage.scanProgress();
      ScanProgress snapshotProgress = snapshotPage.scanProgress();
      assertEquals(liveProgress.kind(), snapshotProgress.kind());
      assertEquals(liveProgress.requestedStart(), snapshotProgress.requestedStart());
      assertEquals(liveProgress.requestedEnd(), snapshotProgress.requestedEnd());
      assertEquals(liveProgress.scannedStart(), snapshotProgress.scannedStart());
      assertEquals(liveProgress.scannedEnd(), snapshotProgress.scannedEnd());
      assertEquals(liveProgress.complete(), snapshotProgress.complete());
      assertEquals(liveProgress.stopReason(), snapshotProgress.stopReason());
      assertTrue(snapshotProgress.elapsedMs() >= 0L);

      liveCursor = livePage.nextCursor();
      snapshotCursor = snapshotPage.nextCursor();
      pages++;
      assertTrue(pages < 32);
      if (liveCursor == null) {
        break;
      }
    }
  }

  private static void populateBatchDemangleFixture(ProgramHolder holder) {
    holder.inTransaction(
        program -> {
          program.setExecutableFormat("Executable and Linking Format (ELF)");
          Address base = initCodeBlock(program, 0x700000L, 0x1000);
          FunctionManager fm = program.getFunctionManager();
          SymbolTable st = program.getSymbolTable();
          createRetFunction(fm, "_ZN6engine4core6Parser5parseEPKc", base);
          createRetFunction(fm, "_ZN6engine4core6Parser5resetEv", base.add(0x20));
          st.createLabel(base.add(0x40), "_ZN6engine7versionE", SourceType.IMPORTED);
          st.createLabel(base.add(0x60), "_Z999broken_symbol$$$", SourceType.IMPORTED);
          createRetFunction(fm, "plain_entry", base.add(0x80));
        });
  }

  private static List<String> summarizeSymbols(
      app.byteland.ghidra.service.symbol.SymbolService symbolService) {
    Page<SymbolResource> page =
        symbolService.listSymbols(
            new SymbolQuery(
                UNBOUNDED_SCAN, null, null, null, null, null, true, 100, null));
    List<String> summary = new ArrayList<>();
    for (SymbolResource item : page.items()) {
      summary.add(
          item.address()
              + "|"
              + item.namespace()
              + "|"
              + item.name()
              + "|"
              + item.primary()
              + "|"
              + item.demangledName());
    }
    return summary;
  }

  private static Address initCodeBlock(ProgramDB program, long startOffset, int size)
      throws Exception {
    AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
    Address base = space.getAddress(startOffset);
    byte[] bytes = new byte[size];
    for (int i = 0; i < size; i += 0x20) {
      bytes[i] = (byte) 0xc3;
    }
    program
        .getMemory()
        .createInitializedBlock(
            ".text", base, new ByteArrayInputStream(bytes), bytes.length, TaskMonitor.DUMMY, false);
    return base;
  }

  private static Function createRetFunction(FunctionManager fm, String name, Address entry)
      throws Exception {
    return fm.createFunction(
        name, entry, new AddressSet(entry, entry), SourceType.IMPORTED);
  }

  private static void endAmbientTransaction(GhidraScript script) {
    try {
      script.end(true);
    } catch (Exception ignored) {
      // No ambient script transaction was active.
    }
  }
}
