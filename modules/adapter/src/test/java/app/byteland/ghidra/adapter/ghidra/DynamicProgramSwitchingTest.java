package app.byteland.ghidra.adapter.ghidra;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.agent.AgentDispatcher;
import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.analysis.AnalysisResource;
import app.byteland.ghidra.service.decompilation.DecompilationResource;
import app.byteland.ghidra.service.function.FunctionService.FunctionAttributePatch;
import app.byteland.ghidra.service.listing.InstructionResource;
import app.byteland.ghidra.service.symbol.SymbolService.DemangleResult;
import ghidra.framework.cmd.Command;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.task.TaskMonitor;
import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class DynamicProgramSwitchingTest {

  private static void addInitializedRamBlock(GhidraTestSupport.ProgramHolder holder, byte fill) {
    holder.inTransaction(
        program -> {
          Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x401000);
          byte[] initial = new byte[64];
          java.util.Arrays.fill(initial, fill);
          program
              .getMemory()
              .createInitializedBlock(
                  ".text",
                  start,
                  new ByteArrayInputStream(initial),
                  initial.length,
                  ghidra.util.task.TaskMonitor.DUMMY,
                  false);
        });
  }

  @Test
  void switchesTargetProgramDynamicallyAcrossRealProgramsAndReleasesOnClose() {
    try (var alphaHolder = GhidraTestSupport.createX64Program("alpha.elf");
        var betaHolder = GhidraTestSupport.createX64Program("beta.elf")) {
      addInitializedRamBlock(alphaHolder, (byte) 0x90);
      addInitializedRamBlock(betaHolder, (byte) 0xc3);

      Program alpha = alphaHolder.program();
      Program beta = betaHolder.program();
      AtomicReference<Program> active = new AtomicReference<>(alpha);
      GhidraSession session = new GhidraSession(active::get);
      List<Program> closedPrograms = new ArrayList<>();
      session.onProgramClosed(closedPrograms::add);

      try (var services = GhidraServiceFactory.create(session, "gui-fallback")) {
        assertEquals("alpha.elf", services.currentProgramName());
        assertEquals("alpha.elf", services.programService().getProgram().name());
        assertEquals(
            "9090",
            services
                .memoryService()
                .readMemoryRange("0x401000", 2, ByteSequence.Encoding.HEX)
                .bytes()
                .data());

        // Write bytes to alpha.elf through TransactionRunner and MemoryService on the dynamic host.
        services
            .transactionRunner()
            .run(
                () -> {
                  services
                      .memoryService()
                      .patchMemory(
                          "0x401000", new ByteSequence(ByteSequence.Encoding.HEX, "deadbeef", 4));
                  return null;
                });
        assertEquals(
            "deadbeef",
            services
                .memoryService()
                .readMemoryRange("0x401000", 4, ByteSequence.Encoding.HEX)
                .bytes()
                .data());
        assertEquals(
            "c3c3c3c3",
            java.util.HexFormat.of()
                .formatHex(
                    betaChecksBytes(beta, 0x401000, 4)));

        // Switch active tab to beta.elf and verify reads, mutations, commands, and analysis status route to beta.elf.
        active.set(beta);
        assertEquals("beta.elf", services.currentProgramName());
        assertEquals("beta.elf", services.programService().getProgram().name());
        assertEquals(
            "c3c3",
            services
                .memoryService()
                .readMemoryRange("0x401000", 2, ByteSequence.Encoding.HEX)
                .bytes()
                .data());
        services
            .transactionRunner()
            .run(
                () -> {
                  services
                      .memoryService()
                      .patchMemory(
                          "0x401000", new ByteSequence(ByteSequence.Encoding.HEX, "cafebabe", 4));
                  return null;
                });
        assertEquals(
            "cafebabe",
            services
                .memoryService()
                .readMemoryRange("0x401000", 4, ByteSequence.Encoding.HEX)
                .bytes()
                .data());
        assertEquals(
            "deadbeef",
            java.util.HexFormat.of().formatHex(betaChecksBytes(alpha, 0x401000, 4)));
        assertEquals("IDLE", services.analysisService().getStatus().status().name());

        List<Program> commandTargets = new ArrayList<>();
        session.runCommand(
            new Command<>() {
              @Override
              public boolean applyTo(Program program) {
                commandTargets.add(program);
                return true;
              }

              @Override
              public String getStatusMsg() {
                return null;
              }

              @Override
              public String getName() {
                return "RecordTarget";
              }
            },
            "command failed");
        assertEquals(List.of(beta), commandTargets);

        // Close alpha.elf and verify cached FlatProgramAPI eviction and listener callback.
        active.set(alpha);
        FlatProgramAPI cachedAlphaApi = session.flatApi();
        assertSame(cachedAlphaApi, session.flatApi());
        session.notifyProgramClosed(alpha);
        assertEquals(List.of(alpha), closedPrograms);
        assertNotSame(cachedAlphaApi, session.flatApi());

        // Clear active program and verify fallback name and clean error.
        active.set(null);
        assertEquals("gui-fallback", services.currentProgramName());
        assertThrows(
            IllegalStateException.class, () -> services.programService().getProgram());
        assertThrows(IllegalStateException.class, session::flatApi);
      }
    }
  }

  @Test
  void pinsProgramAcrossTransactionAndRevertsTemporaryChanges() {
    try (var alphaHolder = GhidraTestSupport.createX64Program("alpha.elf");
        var betaHolder = GhidraTestSupport.createX64Program("beta.elf")) {
      addInitializedRamBlock(alphaHolder, (byte) 0x11);
      addInitializedRamBlock(betaHolder, (byte) 0x22);

      Program alpha = alphaHolder.program();
      Program beta = betaHolder.program();
      AtomicReference<Program> active = new AtomicReference<>(alpha);
      GhidraSession session = new GhidraSession(active::get);

      session.withTransaction(
          () -> {
            FlatProgramAPI pinnedApi = session.flatApi();
            assertSame(alpha, session.currentProgram());
            assertSame(alpha, pinnedApi.getCurrentProgram());

            // External tab switch occurs before the outer transaction completes.
            active.set(beta);
            assertSame(alpha, session.currentProgram());
            assertSame(pinnedApi, session.flatApi());
            assertSame(alpha, session.withTransaction(session::currentProgram));
            pinnedApi.setBytes(session.parseAddress("0x401000"), new byte[] {0x55});
            assertThrows(
                IllegalStateException.class,
                () -> session.withProgramTransaction(beta, () -> "wrong-program"));
            return null;
          });

      assertEquals((byte) 0x55, betaChecksBytes(alpha, 0x401000, 1)[0]);
      assertEquals((byte) 0x22, betaChecksBytes(beta, 0x401000, 1)[0]);
      assertSame(beta, session.currentProgram());

      // Temporary changes on beta.elf roll back cleanly when the block completes.
      session.withTemporaryChanges(
          () -> {
            session.flatApi().setBytes(session.parseAddress("0x401000"), new byte[] {0x77});
            assertEquals((byte) 0x77, session.flatApi().getBytes(session.parseAddress("0x401000"), 1)[0]);
            return null;
          });
      assertEquals((byte) 0x22, betaChecksBytes(beta, 0x401000, 1)[0]);
      assertTrue(!beta.isChanged() || betaChecksBytes(beta, 0x401000, 1)[0] == 0x22);
    }
  }

  @Test
  void decompilationListingScanAndDemanglingSwitchAcrossActivePrograms() throws Exception {
    GhidraTestSupport.x64Language();
    ClassSearcher.search(TaskMonitor.DUMMY);

    try (var alphaHolder = GhidraTestSupport.createX64Program("alpha.elf");
        var betaHolder = GhidraTestSupport.createX64Program("beta.elf")) {
      alphaHolder.inTransaction(
          program -> {
            program.setExecutableFormat("Executable and Linking Format (ELF)");
            Address start =
                program.getAddressFactory().getDefaultAddressSpace().getAddress(0x401000);
            // mov eax, 0x2a; ret
            byte[] code = new byte[] {(byte) 0xb8, 0x2a, 0x00, 0x00, 0x00, (byte) 0xc3};
            program
                .getMemory()
                .createInitializedBlock(
                    ".text",
                    start,
                    new ByteArrayInputStream(code),
                    code.length,
                    TaskMonitor.DUMMY,
                    false);
          });
      betaHolder.inTransaction(
          program -> {
            program.setExecutableFormat("Executable and Linking Format (ELF)");
            Address start =
                program.getAddressFactory().getDefaultAddressSpace().getAddress(0x401000);
            // nop; mov eax, 0x07; ret
            byte[] code = new byte[] {(byte) 0x90, (byte) 0xb8, 0x07, 0x00, 0x00, 0x00, (byte) 0xc3};
            program
                .getMemory()
                .createInitializedBlock(
                    ".text",
                    start,
                    new ByteArrayInputStream(code),
                    code.length,
                    TaskMonitor.DUMMY,
                    false);
          });

      Program alpha = alphaHolder.program();
      Program beta = betaHolder.program();
      AtomicReference<Program> active = new AtomicReference<>(alpha);
      GhidraSession session = new GhidraSession(active::get);

      try (var services = GhidraServiceFactory.create(session, "gui-fallback")) {
        // Create mangled function on alpha.elf, list instructions, demangle, and decompile.
        services
            .transactionRunner()
            .run(() -> services.functionService().createFunction("0x401000", "_ZN5alpha3runEv", true));
        List<InstructionResource> alphaInsns =
            services
                .listingService()
                .listInstructions(AddressScanOptions.of(null, null, 2_000), 10, null)
                .items();
        assertEquals(List.of("MOV", "RET"), alphaInsns.stream().map(InstructionResource::mnemonic).toList());

        DemangleResult alphaDemangle = services.symbolService().demangleSymbols();
        assertEquals(1, alphaDemangle.renamed());
        DecompilationResource alphaDecomp =
            services
                .decompilationService()
                .decompileFunction("0x401000", DecompilationResource.Format.TEXT, 10_000, false);
        assertEquals("run", alphaDecomp.name());
        assertTrue(alphaDecomp.c().contains("run("));

        // Rename the function on alpha.elf and confirm cache flush updates decompiler output.
        services
            .transactionRunner()
            .run(
                () -> {
                  services
                      .functionService()
                      .patchFunction(
                          "0x401000",
                          "alpha_updated",
                          null,
                          false,
                          null,
                          null,
                          null,
                          FunctionAttributePatch.empty());
                  return null;
                });
        DecompilationResource alphaUpdated =
            services
                .decompilationService()
                .decompileFunction("0x401000", DecompilationResource.Format.TEXT, 10_000, false);
        assertEquals("alpha_updated", alphaUpdated.name());
        assertTrue(alphaUpdated.c().contains("alpha_updated("));

        // Switch active program to beta.elf and verify instruction scan, demangler, and decompiler isolate state.
        active.set(beta);
        services
            .transactionRunner()
            .run(() -> services.functionService().createFunction("0x401000", "_ZN4beta4stepEv", true));
        List<InstructionResource> betaInsns =
            services
                .listingService()
                .listInstructions(AddressScanOptions.of(null, null, 2_000), 10, null)
                .items();
        assertEquals(
            List.of("NOP", "MOV", "RET"),
            betaInsns.stream().map(InstructionResource::mnemonic).toList());

        DemangleResult betaDemangle = services.symbolService().demangleSymbols();
        assertEquals(1, betaDemangle.renamed());
        DecompilationResource betaDecomp =
            services
                .decompilationService()
                .decompileFunction("0x401000", DecompilationResource.Format.TEXT, 10_000, false);
        assertEquals("step", betaDecomp.name());
        assertTrue(betaDecomp.c().contains("step("));

        // Release alpha.elf pool and verify beta.elf decompiler continues to work.
        session.notifyProgramClosed(alpha);
        DecompilationResource betaAfterAlphaClose =
            services
                .decompilationService()
                .decompileFunction("0x401000", DecompilationResource.Format.TEXT, 10_000, false);
        assertEquals("step", betaAfterAlphaClose.name());
      }
    }
  }

  @Test
  void analysisTasksRunAndRestoreOptionsAcrossSwitchedPrograms() throws Exception {
    GhidraTestSupport.x64Language();
    ClassSearcher.search(TaskMonitor.DUMMY);

    try (var alphaHolder = GhidraTestSupport.createX64Program("alpha.elf");
        var betaHolder = GhidraTestSupport.createX64Program("beta.elf")) {
      alphaHolder.inTransaction(
          program -> {
            Address start =
                program.getAddressFactory().getDefaultAddressSpace().getAddress(0x401000);
            byte[] data =
                "alpha_analysis_string\0\0\0\0\0\0\0\0\0\0\0"
                    .getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            program
                .getMemory()
                .createInitializedBlock(
                    ".rodata",
                    start,
                    new ByteArrayInputStream(data),
                    data.length,
                    TaskMonitor.DUMMY,
                    false);
          });
      betaHolder.inTransaction(
          program -> {
            Address start =
                program.getAddressFactory().getDefaultAddressSpace().getAddress(0x401000);
            byte[] data =
                "beta_analysis_string\0\0\0\0\0\0\0\0\0\0\0\0"
                    .getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            program
                .getMemory()
                .createInitializedBlock(
                    ".rodata",
                    start,
                    new ByteArrayInputStream(data),
                    data.length,
                    TaskMonitor.DUMMY,
                    false);
          });

      Program alpha = alphaHolder.program();
      Program beta = betaHolder.program();
      AtomicReference<Program> active = new AtomicReference<>(alpha);
      GhidraSession session = new GhidraSession(active::get);

      try (var services = GhidraServiceFactory.create(session, "gui-fallback")) {
        AnalysisResource startedAlpha =
            services.analysisService().startAnalysis(List.of("ASCII Strings"));
        assertEquals(AnalysisResource.Kind.BRIDGE, startedAlpha.kind());

        // Switch active tab to beta.elf while alpha.elf finishes analysis.
        active.set(beta);
        assertEquals(false, services.analysisService().getStatus().analyzed());
        assertEquals(0L, beta.getListing().getNumDefinedData());

        active.set(alpha);
        AnalysisResource completedAlpha = awaitAnalysisCompletion(services);
        assertEquals(AnalysisResource.Status.COMPLETED, completedAlpha.status());
        assertTrue(completedAlpha.analyzed());
        assertTrue(alpha.getListing().getNumDefinedData() > 0);
        assertTrue(
            alpha.getOptions(Program.ANALYSIS_PROPERTIES).getBoolean("Stack", false));

        // beta.elf stays unanalyzed until its own task starts.
        active.set(beta);
        assertEquals(false, services.analysisService().getStatus().analyzed());
        services.analysisService().startAnalysis(List.of("ASCII Strings"));
        AnalysisResource completedBeta = awaitAnalysisCompletion(services);
        assertEquals(AnalysisResource.Status.COMPLETED, completedBeta.status());
        assertTrue(completedBeta.analyzed());
        assertTrue(beta.getListing().getNumDefinedData() > 0);

        session.notifyProgramClosed(alpha);
        assertTrue(services.analysisService().getStatus().analyzed());
      }
    }
  }

  @Test
  @SuppressWarnings("unchecked")
  void concurrentDispatcherReadsAndDecompilationsSwitchCleanlyUnderRunExclusive() throws Exception {
    GhidraTestSupport.x64Language();
    ClassSearcher.search(TaskMonitor.DUMMY);

    try (var alphaHolder = GhidraTestSupport.createX64Program("alpha.elf");
        var betaHolder = GhidraTestSupport.createX64Program("beta.elf")) {
      alphaHolder.inTransaction(
          program -> {
            Address start =
                program.getAddressFactory().getDefaultAddressSpace().getAddress(0x401000);
            byte[] code = new byte[] {(byte) 0xb8, 0x2a, 0x00, 0x00, 0x00, (byte) 0xc3};
            program
                .getMemory()
                .createInitializedBlock(
                    ".text",
                    start,
                    new ByteArrayInputStream(code),
                    code.length,
                    TaskMonitor.DUMMY,
                    false);
          });
      betaHolder.inTransaction(
          program -> {
            Address start =
                program.getAddressFactory().getDefaultAddressSpace().getAddress(0x401000);
            byte[] code = new byte[] {(byte) 0xb8, 0x07, 0x00, 0x00, 0x00, (byte) 0xc3};
            program
                .getMemory()
                .createInitializedBlock(
                    ".text",
                    start,
                    new ByteArrayInputStream(code),
                    code.length,
                    TaskMonitor.DUMMY,
                    false);
          });

      Program alpha = alphaHolder.program();
      Program beta = betaHolder.program();
      AtomicReference<Program> active = new AtomicReference<>(alpha);
      GhidraSession session = new GhidraSession(active::get);

      try (var services = GhidraServiceFactory.create(session, "gui-fallback");
          AgentDispatcher dispatcher = new AgentDispatcher(services, "dynamic-concurrency");
          ExecutorService pool = Executors.newFixedThreadPool(6)) {
        dispatcher.dispatch(
            "function.create",
            Map.of(
                "resource", Map.of("entry", "0x401000", "name", "alpha_fn"),
                "disassemble", true));
        dispatcher.runExclusive(() -> active.set(beta));
        dispatcher.dispatch(
            "function.create",
            Map.of(
                "resource", Map.of("entry", "0x401000", "name", "beta_fn"),
                "disassemble", true));
        dispatcher.runExclusive(() -> active.set(alpha));

        CountDownLatch startGate = new CountDownLatch(1);
        CountDownLatch alphaObserved = new CountDownLatch(6);
        AtomicBoolean switchedToBeta = new AtomicBoolean(false);
        AtomicBoolean stopReaders = new AtomicBoolean(false);

        List<Future<Void>> readers = new ArrayList<>();
        for (int r = 0; r < 6; r++) {
          final int readerId = r;
          readers.add(
              pool.submit(
                  () -> {
                    startGate.await();
                    boolean countedAlpha = false;
                    int step = 0;
                    while (!stopReaders.get()) {
                      boolean betaOnly = switchedToBeta.get();
                      switch ((readerId + step++) % 4) {
                        case 0 -> {
                          Map<String, Object> info =
                              (Map<String, Object>) dispatcher.dispatch("session.get", Map.of());
                          String name = String.valueOf(info.get("program_name"));
                          if (betaOnly) {
                            assertEquals("beta.elf", name);
                          } else {
                            assertTrue("alpha.elf".equals(name) || "beta.elf".equals(name));
                          }
                        }
                        case 1 -> {
                          Map<String, Object> resolved =
                              (Map<String, Object>)
                                  dispatcher.dispatch(
                                      "address.resolve",
                                      Map.of("selector", Map.of("address", "0x401000")));
                          Map<String, Object> fn =
                              (Map<String, Object>) resolved.get("function");
                          String fnName = String.valueOf(fn.get("name"));
                          if (betaOnly) {
                            assertEquals("beta_fn", fnName);
                          } else {
                            assertTrue("alpha_fn".equals(fnName) || "beta_fn".equals(fnName));
                          }
                        }
                        case 2 -> {
                          Map<String, Object> mem =
                              (Map<String, Object>)
                                  dispatcher.dispatch(
                                      "memory.read",
                                      Map.of(
                                          "selector", Map.of("address", "0x401000"),
                                          "length", 2));
                          Map<String, Object> bytes = (Map<String, Object>) mem.get("bytes");
                          String hex = String.valueOf(bytes.get("data"));
                          if (betaOnly) {
                            assertEquals("b807", hex);
                          } else {
                            assertTrue("b82a".equals(hex) || "b807".equals(hex));
                          }
                        }
                        default -> {
                          Map<String, Object> decomp =
                              (Map<String, Object>)
                                  dispatcher.dispatch(
                                      "decompilation.get",
                                      Map.of(
                                          "selector", Map.of("entry", "0x401000"),
                                          "format", "text"));
                          String fnName = String.valueOf(decomp.get("name"));
                          if (betaOnly) {
                            assertEquals("beta_fn", fnName);
                          } else {
                            assertTrue("alpha_fn".equals(fnName) || "beta_fn".equals(fnName));
                          }
                        }
                      }
                      if (!countedAlpha) {
                        countedAlpha = true;
                        alphaObserved.countDown();
                      }
                    }
                    return null;
                  }));
        }

        startGate.countDown();
        assertTrue(alphaObserved.await(15, TimeUnit.SECONDS));

        dispatcher.runExclusive(
            () -> {
              active.set(beta);
              switchedToBeta.set(true);
              session.notifyProgramClosed(alpha);
            });

        Thread.sleep(100L);
        stopReaders.set(true);
        for (Future<Void> reader : readers) {
          reader.get(20, TimeUnit.SECONDS);
        }
        assertEquals("beta.elf", dispatcher.getProgramName());
      }
    }
  }

  @Test
  @SuppressWarnings("unchecked")
  void cDeclarationsAndSignaturePatchesIsolateAcrossSwitchedPrograms() throws Exception {
    try (var alphaHolder = GhidraTestSupport.createX64Program("alpha.elf");
        var betaHolder = GhidraTestSupport.createX64Program("beta.elf")) {
      alphaHolder.inTransaction(
          program -> {
            Address start =
                program.getAddressFactory().getDefaultAddressSpace().getAddress(0x401000);
            byte[] code = new byte[] {(byte) 0xb8, 0x2a, 0x00, 0x00, 0x00, (byte) 0xc3};
            program
                .getMemory()
                .createInitializedBlock(
                    ".text",
                    start,
                    new ByteArrayInputStream(code),
                    code.length,
                    TaskMonitor.DUMMY,
                    false);
          });
      betaHolder.inTransaction(
          program -> {
            Address start =
                program.getAddressFactory().getDefaultAddressSpace().getAddress(0x401000);
            byte[] code = new byte[] {(byte) 0xb8, 0x07, 0x00, 0x00, 0x00, (byte) 0xc3};
            program
                .getMemory()
                .createInitializedBlock(
                    ".text",
                    start,
                    new ByteArrayInputStream(code),
                    code.length,
                    TaskMonitor.DUMMY,
                    false);
          });

      Program alpha = alphaHolder.program();
      Program beta = betaHolder.program();
      AtomicReference<Program> active = new AtomicReference<>(alpha);
      GhidraSession session = new GhidraSession(active::get);

      try (var services = GhidraServiceFactory.create(session, "gui-fallback");
          AgentDispatcher dispatcher = new AgentDispatcher(services, "dynamic-c-decls")) {
        Map<String, Object> parsedEnvelope =
            (Map<String, Object>)
                dispatcher.dispatch(
                    "data_type.parse_c",
                    Map.of(
                        "declarations", "typedef struct { int fd; } AlphaHandle;",
                        "category_path", "/alpha",
                        "projection", Map.of("fields", List.of("name", "category_path"))));
        List<Map<String, Object>> parsed =
            (List<Map<String, Object>>) parsedEnvelope.get("items");
        assertEquals(1, parsed.size());
        assertEquals("/alpha/AlphaHandle", parsed.get(0).get("path"));
        assertEquals("AlphaHandle", parsed.get(0).get("name"));
        assertEquals("/alpha", parsed.get(0).get("category_path"));
        assertEquals(false, parsed.get(0).containsKey("length"));

        dispatcher.dispatch(
            "function.create",
            Map.of(
                "resource", Map.of("entry", "0x401000", "name", "alpha_open"),
                "disassemble", true));
        dispatcher.dispatch(
            "function.patch",
            Map.of(
                "selector", Map.of("entry", "0x401000"),
                "patch", Map.of("signature", "int alpha_open(const AlphaHandle *handle)")));
        Map<String, Object> projectedAlpha =
            (Map<String, Object>)
                dispatcher.dispatch(
                    "function.get",
                    Map.of(
                        "selector", Map.of("entry", "0x401000"),
                        "projection", Map.of("fields", List.of("name", "signature"))));
        assertEquals("alpha_open", projectedAlpha.get("name"));
        assertTrue(String.valueOf(projectedAlpha.get("signature")).contains("AlphaHandle"));
        assertEquals(false, projectedAlpha.containsKey("calling_convention"));

        // Switch active program to beta.elf and verify AlphaHandle stays isolated to alpha.elf.
        dispatcher.runExclusive(() -> active.set(beta));
        dispatcher.dispatch(
            "function.create",
            Map.of(
                "resource", Map.of("entry", "0x401000", "name", "beta_open"),
                "disassemble", true));
        assertThrows(
            IllegalArgumentException.class,
            () ->
                dispatcher.dispatch(
                    "function.patch",
                    Map.of(
                        "selector", Map.of("entry", "0x401000"),
                        "patch", Map.of("signature", "int beta_open(const AlphaHandle *handle)"))));
      }
    }
  }

  private static AnalysisResource awaitAnalysisCompletion(
      app.byteland.ghidra.service.BridgeServices services) throws InterruptedException {
    long deadlineNanos = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(30);
    while (System.nanoTime() < deadlineNanos) {
      AnalysisResource current = services.analysisService().getStatus();
      if (current.kind() == AnalysisResource.Kind.BRIDGE
          && current.status() != AnalysisResource.Status.RUNNING) {
        return current;
      }
      Thread.sleep(20L);
    }
    throw new AssertionError("Timed out waiting for analysis task to finish");
  }

  private static byte[] betaChecksBytes(Program program, long offset, int length) {
    try {
      Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
      byte[] out = new byte[length];
      program.getMemory().getBytes(addr, out);
      return out;
    } catch (Exception error) {
      throw new IllegalStateException(error);
    }
  }
}
