package app.byteland.ghidra.adapter.ghidra;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.adapter.ghidra.GhidraTestSupport.ProgramHolder;
import app.byteland.ghidra.adapter.ghidra.function.FunctionServiceImpl;
import app.byteland.ghidra.adapter.ghidra.symbol.SymbolServiceImpl;
import app.byteland.ghidra.agent.AgentDispatcher;
import app.byteland.ghidra.api.ApiException;
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
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.DefaultAddressFactory;
import ghidra.program.model.address.GenericAddressSpace;
import ghidra.program.model.listing.CommentType;
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
import java.util.concurrent.locks.LockSupport;
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

  @Test
  void interruptedForegroundLookupDoesNotPoisonCacheForConcurrentReaders() throws Exception {
    try (ProgramHolder holder = GhidraTestSupport.createX64Program("cpp_interrupt_safe")) {
      String targetSymbol = "_ZN9interrupt7Service6handleEi";
      Address[] entryHolder = new Address[1];
      holder.inTransaction(
          program -> {
            program.setExecutableFormat("Executable and Linking Format (ELF)");
            Address base = initCodeBlock(program, 0xa00000L, 0x100);
            Function fn = createRetFunction(program.getFunctionManager(), targetSymbol, base);
            entryHolder[0] = fn.getEntryPoint();
          });

      CountDownLatch firstEntered = new CountDownLatch(1);
      CountDownLatch secondWaiting = new CountDownLatch(1);
      AtomicInteger calls = new AtomicInteger();

      CppDemangler interruptOnceDemangler =
          (program, name, address) -> {
            int attempt = calls.incrementAndGet();
            if (attempt == 1) {
              firstEntered.countDown();
              try {
                assertTrue(secondWaiting.await(5, TimeUnit.SECONDS));
                Thread.sleep(60_000L);
              } catch (InterruptedException interrupted) {
                // Return an empty result with the interrupt flag set to match GnuDemangler.
                Thread.currentThread().interrupt();
                return List.of();
              }
            }
            return DemanglerUtil.demangle(program, name, address);
          };

      GhidraScript script = GhidraTestSupport.scriptFor(holder.program());
      try (GhidraSession session =
              new GhidraSession(script, CppSymbolIndexConfig.defaults(), interruptOnceDemangler);
          ExecutorService pool = Executors.newFixedThreadPool(2)) {
        AtomicReference<Thread> firstThread = new AtomicReference<>();
        Future<String> interruptedReader =
            pool.submit(
                () -> {
                  firstThread.set(Thread.currentThread());
                  return session
                      .cppSymbols()
                      .demangled(holder.program(), targetSymbol, entryHolder[0]);
                });
        assertTrue(firstEntered.await(5, TimeUnit.SECONDS));

        Future<String> siblingReader =
            pool.submit(
                () -> {
                  secondWaiting.countDown();
                  return session
                      .cppSymbols()
                      .demangled(holder.program(), targetSymbol, entryHolder[0]);
                });
        assertTrue(secondWaiting.await(5, TimeUnit.SECONDS));
        Thread.sleep(20L);
        firstThread.get().interrupt();

        assertNull(interruptedReader.get(5, TimeUnit.SECONDS));
        String siblingResult = siblingReader.get(5, TimeUnit.SECONDS);
        assertNotNull(siblingResult);
        assertEquals(
            siblingResult,
            session.cppSymbols().demangled(holder.program(), targetSymbol, entryHolder[0]));
        assertEquals(2, calls.get());
      } finally {
        endAmbientTransaction(script);
      }
    }
  }

  @Test
  void prewarmerRunsConcurrentlyWithAgentDispatcherReadsWritesAndRollbacks() throws Exception {
    try (ProgramHolder holder = GhidraTestSupport.createX64Program("cpp_dispatcher_concurrency")) {
      AtomicReference<Long> extSymbolId = new AtomicReference<>();
      holder.inTransaction(
          program -> {
            program.setExecutableFormat("Executable and Linking Format (ELF)");
            AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
            Address base = space.getAddress(0x10000L);
            byte[] bytes = new byte[0x2000];
            // 0x10000..0x10005: mov eax, 0x2a; ret
            bytes[0x00] = (byte) 0xb8;
            bytes[0x01] = 0x2a;
            bytes[0x05] = (byte) 0xc3;
            // 0x10020..0x10025: call 0x10000 (e8 db ff ff ff); ret
            bytes[0x20] = (byte) 0xe8;
            bytes[0x21] = (byte) 0xdb;
            bytes[0x22] = (byte) 0xff;
            bytes[0x23] = (byte) 0xff;
            bytes[0x24] = (byte) 0xff;
            bytes[0x25] = (byte) 0xc3;
            for (int off = 0x40; off < 0x120; off += 0x20) {
              bytes[off] = (byte) 0xb8;
              bytes[off + 1] = 0x01;
              bytes[off + 5] = (byte) 0xc3;
            }

            program
                .getMemory()
                .createInitializedBlock(
                    ".text",
                    base,
                    new ByteArrayInputStream(bytes),
                    bytes.length,
                    TaskMonitor.DUMMY,
                    false);

            disassembleRange(program, base, base.add(5));
            disassembleRange(program, base.add(0x20), base.add(0x25));
            for (int off = 0x40; off < 0x100; off += 0x20) {
              disassembleRange(program, base.add(off), base.add(off + 5));
            }

            FunctionManager fm = program.getFunctionManager();
            Function callee =
                fm.createFunction(
                    "_ZN4demo11callee_funcEi",
                    base,
                    new AddressSet(base, base.add(5)),
                    SourceType.USER_DEFINED);
            Function caller =
                fm.createFunction(
                    "_ZN4demo11caller_funcEi",
                    base.add(0x20),
                    new AddressSet(base.add(0x20), base.add(0x25)),
                    SourceType.USER_DEFINED);
            for (int w = 0; w < 3; w++) {
              Address fnAddr = base.add(0x40 + (w * 0x20L));
              fm.createFunction(
                  "mutable_target_" + w,
                  fnAddr,
                  new AddressSet(fnAddr, fnAddr.add(5)),
                  SourceType.USER_DEFINED);
            }
            Address rollbackAddr = base.add(0xa0);
            fm.createFunction(
                "rollback_target",
                rollbackAddr,
                new AddressSet(rollbackAddr, rollbackAddr.add(5)),
                SourceType.USER_DEFINED);

            program
                .getReferenceManager()
                .addMemoryReference(
                    caller.getEntryPoint(),
                    callee.getEntryPoint(),
                    RefType.UNCONDITIONAL_CALL,
                    SourceType.USER_DEFINED,
                    0);
            program.getListing().setComment(base, CommentType.EOL, "COMMITTED_INIT");

            SymbolTable st = program.getSymbolTable();
            for (int i = 0; i < 36; i++) {
              st.createLabel(
                  base.add(0x200 + (i * 4L)),
                  String.format("_ZN5bench10symbol_%03dEi", i),
                  SourceType.IMPORTED);
            }
            for (int i = 0; i < 18; i++) {
              st.createLabel(
                  base.add(0x400 + (i * 4L)),
                  String.format("__ZN5bench10darwin_%03dEv", i),
                  SourceType.IMPORTED);
            }
            for (int i = 0; i < 18; i++) {
              st.createLabel(
                  base.add(0x600 + (i * 4L)),
                  String.format("?msvcSym%03d@bench@@YAXXZ", i),
                  SourceType.IMPORTED);
            }

            ExternalLocation ext =
                program
                    .getExternalManager()
                    .addExtFunction("libstdc++.so.6", "_ZNSolsEi", null, SourceType.IMPORTED);
            extSymbolId.set(ext.getSymbol().getID());
          });

      AtomicBoolean heldLockDuringPrewarmOrSharedRead = new AtomicBoolean(false);
      ThreadLocal<Boolean> inSharedReadDispatch = ThreadLocal.withInitial(() -> Boolean.FALSE);
      AtomicInteger pacedCalls = new AtomicInteger();
      AtomicInteger totalDemangleCalls = new AtomicInteger();
      AtomicReference<GhidraSession> sessionRef = new AtomicReference<>();

      CppDemangler pacedDemangler =
          (program, name, address) -> {
            GhidraSession active = sessionRef.get();
            boolean onPrewarmThread =
                Thread.currentThread().getName().startsWith("ghidra-cpp-index-");
            if (active != null
                && active.holdsExecutionLock()
                && (onPrewarmThread || Boolean.TRUE.equals(inSharedReadDispatch.get()))) {
              heldLockDuringPrewarmOrSharedRead.set(true);
            }
            totalDemangleCalls.incrementAndGet();
            if (pacedCalls.incrementAndGet() <= 32) {
              LockSupport.parkNanos(250_000L);
            }
            return DemanglerUtil.demangle(program, name, address);
          };

      GhidraScript script = GhidraTestSupport.scriptFor(holder.program());
      script.start();
      try {
        GhidraSession session =
            new GhidraSession(
                script,
                new CppSymbolIndexConfig(4096, 16L * 1024 * 1024, 8),
                pacedDemangler);
        sessionRef.set(session);
        BridgeServices services = GhidraServiceFactory.create(session);
        try (AgentDispatcher dispatcher =
                new AgentDispatcher(services, "cpp-prewarm-dispatcher-concurrency");
            ExecutorService pool = Executors.newFixedThreadPool(14)) {
          CountDownLatch startGate = new CountDownLatch(1);
          AtomicBoolean stopReaders = new AtomicBoolean(false);
          AtomicReference<Throwable> failure = new AtomicReference<>();
          String externalIdText = String.valueOf(extSymbolId.get());

          List<Future<?>> readers = new ArrayList<>();
          for (int r = 0; r < 10; r++) {
            final int readerId = r;
            readers.add(
                pool.submit(
                    () -> {
                      try {
                        startGate.await();
                        int step = 0;
                        while (!stopReaders.get()) {
                          int currentStep = step++;
                          boolean sharedRead = ((readerId + currentStep) % 7 != 6) || (currentStep % 2 == 0);
                          inSharedReadDispatch.set(sharedRead);
                          try {
                            runDispatcherReadStep(dispatcher, externalIdText, readerId, currentStep);
                          } finally {
                            inSharedReadDispatch.remove();
                          }
                        }
                      } catch (Throwable error) {
                        failure.compareAndSet(null, error);
                      }
                    }));
          }

          List<Future<?>> writers = new ArrayList<>();
          for (int w = 0; w < 3; w++) {
            final int writerId = w;
            writers.add(
                pool.submit(
                    () -> {
                      startGate.await();
                      for (int iter = 0; iter < 10; iter++) {
                        runDispatcherWriteStep(dispatcher, writerId, iter);
                      }
                      return null;
                    }));
          }

          startGate.countDown();
          for (Future<?> writer : writers) {
            writer.get(30, TimeUnit.SECONDS);
          }
          stopReaders.set(true);
          for (Future<?> reader : readers) {
            reader.get(30, TimeUnit.SECONDS);
          }

          if (failure.get() != null) {
            throw new AssertionError(
                "Concurrent CppSymbolPrewarmer + AgentDispatcher test failed", failure.get());
          }
          assertFalse(heldLockDuringPrewarmOrSharedRead.get());

          assertTrue(session.cppSymbols().awaitPrewarm(Duration.ofSeconds(15)));
          assertNotNull(
              session
                  .cppSymbols()
                  .symbolSnapshotIfCurrent(holder.program(), holder.program().getMinAddress()));

          int callsBeforePostSweep = totalDemangleCalls.get();
          runDispatcherReadStep(dispatcher, externalIdText, 0, 0);
          runDispatcherReadStep(dispatcher, externalIdText, 1, 0);
          assertEquals(callsBeforePostSweep, totalDemangleCalls.get());

          @SuppressWarnings("unchecked")
          Map<String, Object> rollbackFn =
              (Map<String, Object>)
                  dispatcher.dispatch(
                      "function.get", Map.of("selector", Map.of("entry", "ram:000100a0")));
          assertEquals("rollback_target", rollbackFn.get("name"));
        }
      } finally {
        endAmbientTransaction(script);
      }
    }
  }

  @SuppressWarnings("unchecked")
  private static void runDispatcherReadStep(
      AgentDispatcher dispatcher, String externalIdText, int readerId, int step) throws Exception {
    switch ((readerId + step) % 7) {
      case 0 -> {
        int pageLimit = (step % 2 == 0) ? 25 : 250;
        String cursor = null;
        int seenBenchSymbols = 0;
        int pages = 0;
        do {
          Map<String, Object> params =
              cursor == null
                  ? Map.of("page", Map.of("limit", pageLimit))
                  : Map.of("page", Map.of("limit", pageLimit, "cursor", cursor));
          Map<String, Object> page = (Map<String, Object>) dispatcher.dispatch("symbol.list", params);
          List<Map<String, Object>> items = (List<Map<String, Object>>) page.get("items");
          for (Map<String, Object> item : items) {
            String name = String.valueOf(item.get("name"));
            assertFalse(
                name.startsWith("_ZN8rollback"),
                "Rolled-back symbol leaked into symbol.list: " + name);
            if (name.startsWith("_ZN5bench10symbol_")) {
              assertNotNull(item.get("demangled_name"), "Missing demangled_name for " + name);
              seenBenchSymbols++;
            } else if (name.startsWith("__ZN5bench10darwin_")) {
              assertNull(item.get("demangled_name"));
            }
          }
          Map<String, Object> pageMeta = (Map<String, Object>) page.get("page");
          cursor = pageMeta == null ? null : (String) pageMeta.get("next_cursor");
          pages++;
          assertTrue(pages < 20);
        } while (cursor != null);
        if (pageLimit == 250) {
          assertEquals(36, seenBenchSymbols);
        } else {
          assertTrue(seenBenchSymbols > 0);
        }
      }
      case 1 -> {
        Map<String, Object> functions =
            (Map<String, Object>)
                dispatcher.dispatch("function.list", Map.of("page", Map.of("limit", 20)));
        List<Map<String, Object>> items = (List<Map<String, Object>>) functions.get("items");
        assertEquals(6, items.size());
        for (Map<String, Object> item : items) {
          String name = String.valueOf(item.get("name"));
          assertFalse(
              name.startsWith("_ZN8rollback"),
              "Rolled-back function name leaked into function.list: " + name);
          if (name.startsWith("_ZN4live14writer") || name.startsWith("_ZN4demo11")) {
            assertNotNull(item.get("demangled_name"), "Missing demangled_name for " + name);
          }
        }
      }
      case 2 -> {
        Map<String, Object> callers =
            (Map<String, Object>)
                dispatcher.dispatch(
                    "function_call.list",
                    Map.of("filter", Map.of("entry", "ram:00010000", "direction", "callers")));
        List<Map<String, Object>> items = (List<Map<String, Object>>) callers.get("items");
        assertFalse(items.isEmpty());
      }
      case 3 -> {
        Map<String, Object> sym =
            (Map<String, Object>)
                dispatcher.dispatch("symbol.get", Map.of("selector", Map.of("id", externalIdText)));
        assertNotNull(sym.get("demangled_name"));
      }
      case 4 -> {
        String format = (step % 2 == 0) ? "document" : "text";
        Map<String, Object> decomp =
            (Map<String, Object>)
                dispatcher.dispatch(
                    "decompilation.get",
                    Map.of(
                        "selector", Map.of("entry", "ram:00010020"),
                        "format", format));
        assertEquals(Boolean.TRUE, decomp.get("completed"));
        if ("document".equals(format)) {
          List<?> lines = (List<?>) decomp.get("lines");
          assertFalse(lines.isEmpty());
        }
      }
      case 5 -> {
        Map<String, Object> comment =
            (Map<String, Object>)
                dispatcher.dispatch(
                    "comment.get",
                    Map.of("selector", Map.of("address", "ram:00010000", "type", "eol")));
        String text = String.valueOf(comment.get("text"));
        assertTrue(
            text.startsWith("COMMITTED_"),
            "Observed uncommitted or rolled-back comment: " + text);
      }
      default -> {
        Map<String, Object> batch =
            (Map<String, Object>)
                dispatcher.dispatch(
                    "batch.execute",
                    Map.of(
                        "transaction_mode",
                        step % 2 == 0 ? "per_item" : "all_or_none",
                        "items",
                        List.of(
                            Map.of(
                                "id",
                                "s1",
                                "method",
                                "symbol.list",
                                "arguments",
                                Map.of("page", Map.of("limit", 10))),
                            Map.of(
                                "id",
                                "f1",
                                "method",
                                "function.list",
                                "arguments",
                                Map.of("page", Map.of("limit", 10))))));
        List<?> items = (List<?>) batch.get("items");
        assertEquals(2, items.size());
      }
    }
  }

  private static void runDispatcherWriteStep(AgentDispatcher dispatcher, int writerId, int iter)
      throws Exception {
    switch ((writerId + iter) % 4) {
      case 0 ->
          dispatcher.dispatch(
              "comment.upsert",
              Map.of(
                  "resource",
                  Map.of(
                      "address", "ram:00010000",
                      "type", "eol",
                      "text", "COMMITTED_COMMENT_" + writerId + "_" + iter)));
      case 1 -> {
        String entry = String.format("ram:000100%02x", 0x40 + (writerId * 0x20));
        String freshMangled = String.format("_ZN4live14writer%d_iter%02dEi", writerId, iter);
        dispatcher.dispatch(
            "function.patch",
            Map.of(
                "selector", Map.of("entry", entry),
                "patch", Map.of("name", freshMangled)));
      }
      case 2 -> {
        ApiException rolledBack =
            assertThrows(
                ApiException.class,
                () ->
                    dispatcher.dispatch(
                        "batch.execute",
                        Map.of(
                            "transaction_mode",
                            "all_or_none",
                            "items",
                            List.of(
                                Map.of(
                                    "id",
                                    "dirty-fn",
                                    "method",
                                    "function.patch",
                                    "arguments",
                                    Map.of(
                                        "selector",
                                        Map.of("entry", "ram:000100a0"),
                                        "patch",
                                        Map.of(
                                            "name",
                                            String.format(
                                                "_ZN8rollback11leaked_%d_%02dEv",
                                                writerId, iter)))),
                                Map.of(
                                    "id",
                                    "dirty-comment",
                                    "method",
                                    "comment.upsert",
                                    "arguments",
                                    Map.of(
                                        "resource",
                                        Map.of(
                                            "address", "ram:00010000",
                                            "type", "eol",
                                            "text", "ROLLBACK_" + writerId + "_" + iter))),
                                Map.of(
                                    "id",
                                    "missing-fn",
                                    "method",
                                    "function.patch",
                                    "arguments",
                                    Map.of(
                                        "selector", Map.of("entry", "ram:00011ff0"),
                                        "patch", Map.of("name", "missing")))))));
        assertEquals(409, rolledBack.status());
        assertEquals("batch_rolled_back", rolledBack.error().code());
      }
      default -> {
        if (iter == 9 && writerId == 0) {
          Map<?, ?> demangled = (Map<?, ?>) dispatcher.dispatch("symbol.demangle", Map.of());
          assertTrue(((Number) demangled.get("renamed")).intValue() >= 36);
        } else {
          dispatcher.dispatch(
              "comment.upsert",
              Map.of(
                  "resource",
                  Map.of(
                      "address", "ram:00010000",
                      "type", "eol",
                      "text", "COMMITTED_EXTRA_" + writerId + "_" + iter)));
        }
      }
    }
  }

  private static void disassembleRange(ProgramDB program, Address start, Address end) {
    new DisassembleCommand(start, new AddressSet(start, end), false)
        .applyTo(program, TaskMonitor.DUMMY);
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
