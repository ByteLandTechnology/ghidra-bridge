package app.byteland.ghidra.adapter.ghidra;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.adapter.ghidra.GhidraTestSupport.ProgramHolder;
import app.byteland.ghidra.agent.AgentDispatcher;
import app.byteland.ghidra.api.ApiException;
import app.byteland.ghidra.service.BridgeServices;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
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

class ProgramDbDispatcherConcurrencyTest {

  private static final class BoundProgramScript extends GhidraScript {
    private BoundProgramScript(Program program) {
      set(program, TaskMonitor.DUMMY);
    }

    @Override
    protected void run() {}
  }

  @Test
  void concurrentProgramDbReadsDecompilationsAndFairWritesPreserveIsolationAndRollback()
      throws Exception {
    try (ProgramHolder holder = GhidraTestSupport.createX64Program("programdb_concurrency")) {
      holder.inTransaction(
          program -> {
            AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
            Address base = space.getAddress(0x10000L);
            byte[] bytes = new byte[0x100];
            // 0x10000..0x10005: mov eax, 0x2a; ret
            bytes[0x00] = (byte) 0xb8;
            bytes[0x01] = 0x2a;
            bytes[0x05] = (byte) 0xc3;
            // 0x10020..0x10025: mov eax, 0x07; ret
            bytes[0x20] = (byte) 0xb8;
            bytes[0x21] = 0x07;
            bytes[0x25] = (byte) 0xc3;
            // 0x10040..0x10043: 32-bit data constant 0x12345678
            bytes[0x40] = 0x78;
            bytes[0x41] = 0x56;
            bytes[0x42] = 0x34;
            bytes[0x43] = 0x12;

            program
                .getMemory()
                .createInitializedBlock(
                    ".text",
                    base,
                    new ByteArrayInputStream(bytes),
                    bytes.length,
                    TaskMonitor.DUMMY,
                    false);

            Address fn1Start = base;
            Address fn1End = base.add(5);
            new DisassembleCommand(fn1Start, new AddressSet(fn1Start, fn1End), false)
                .applyTo(program, TaskMonitor.DUMMY);

            Address fn2Start = base.add(0x20);
            Address fn2End = base.add(0x25);
            new DisassembleCommand(fn2Start, new AddressSet(fn2Start, fn2End), false)
                .applyTo(program, TaskMonitor.DUMMY);

            FunctionManager functionManager = program.getFunctionManager();
            functionManager.createFunction(
                "compute_answer",
                fn1Start,
                new AddressSet(fn1Start, fn1End),
                SourceType.USER_DEFINED);
            functionManager.createFunction(
                "helper_seven",
                fn2Start,
                new AddressSet(fn2Start, fn2End),
                SourceType.USER_DEFINED);

            program.getListing().createData(base.add(0x40), DWordDataType.dataType);
            program.getListing().setComment(fn1Start, CommentType.EOL, "COMMITTED_INIT");
            program
                .getReferenceManager()
                .addMemoryReference(
                    fn1Start, fn2Start, RefType.UNCONDITIONAL_CALL, SourceType.USER_DEFINED, 0);
          });

      BoundProgramScript script = new BoundProgramScript(holder.program());
      script.start();
      try {
        BridgeServices services = GhidraServiceFactory.create(script);
        try (AgentDispatcher dispatcher = new AgentDispatcher(services, "programdb-concurrency");
            ExecutorService pool = Executors.newFixedThreadPool(16)) {
          CountDownLatch startGate = new CountDownLatch(1);
          AtomicBoolean stopReaders = new AtomicBoolean(false);
          AtomicReference<Throwable> failure = new AtomicReference<>();

          List<Future<?>> readers = new ArrayList<>();
          for (int r = 0; r < 12; r++) {
            final int readerId = r;
            readers.add(
                pool.submit(
                    () -> {
                      try {
                        startGate.await();
                        int step = 0;
                        while (!stopReaders.get()) {
                          runReadIteration(dispatcher, readerId, step++);
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
                      for (int iter = 0; iter < 12; iter++) {
                        runWriteIteration(dispatcher, writerId, iter);
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
            throw new AssertionError("Concurrent ProgramDB dispatch failed", failure.get());
          }

          Map<?, ?> finalComment =
              (Map<?, ?>)
                  dispatcher.dispatch(
                      "comment.get",
                      Map.of("selector", Map.of("address", "ram:00010000", "type", "eol")));
          String finalText = String.valueOf(finalComment.get("text"));
          assertTrue(
              finalText.startsWith("COMMITTED_"),
              "Final committed comment must start with COMMITTED_, got: " + finalText);
        }
      } finally {
        script.end(true);
      }
    }
  }

  @SuppressWarnings("unchecked")
  private static void runReadIteration(AgentDispatcher dispatcher, int readerId, int step)
      throws Exception {
    switch ((readerId + step) % 10) {
      case 0 -> {
        Map<String, Object> comment =
            (Map<String, Object>)
                dispatcher.dispatch(
                    "comment.get",
                    Map.of("selector", Map.of("address", "ram:00010000", "type", "eol")));
        String text = String.valueOf(comment.get("text"));
        assertTrue(
            text.startsWith("COMMITTED_"),
            "Reader observed uncommitted or rolled-back ProgramDB state: " + text);
      }
      case 1 -> {
        Map<String, Object> resolved =
            (Map<String, Object>)
                dispatcher.dispatch(
                    "address.resolve", Map.of("selector", Map.of("address", "ram:00010000")));
        assertEquals("ram:00010000", resolved.get("address"));
      }
      case 2 -> {
        Map<String, Object> memory =
            (Map<String, Object>)
                dispatcher.dispatch(
                    "memory.read",
                    Map.of("selector", Map.of("address", "ram:00010000"), "length", 6));
        Map<String, Object> bytes = (Map<String, Object>) memory.get("bytes");
        assertEquals("b82a000000c3", bytes.get("data"));
      }
      case 3 -> {
        String kind =
            switch (step % 3) {
              case 0 -> "all";
              case 1 -> "instruction";
              default -> "data";
            };
        Map<String, Object> units =
            (Map<String, Object>)
                dispatcher.dispatch(
                    "code_unit.list",
                    Map.of(
                        "scan",
                        Map.of("range", Map.of("start", "ram:00010000", "end", "ram:0001004f")),
                        "filter",
                        Map.of("kind", kind),
                        "page",
                        Map.of("limit", 10)));
        List<?> items = (List<?>) units.get("items");
        assertFalse(items.isEmpty());
      }
      case 4 -> {
        Map<String, Object> functions =
            (Map<String, Object>)
                dispatcher.dispatch("function.list", Map.of("page", Map.of("limit", 10)));
        List<?> items = (List<?>) functions.get("items");
        assertEquals(2, items.size());
      }
      case 5 -> {
        Map<String, Object> instructions =
            (Map<String, Object>)
                dispatcher.dispatch(
                    "instruction.list",
                    Map.of(
                        "scan",
                        Map.of("range", Map.of("start", "ram:00010000", "end", "ram:00010030")),
                        "page",
                        Map.of("limit", 10)));
        List<?> items = (List<?>) instructions.get("items");
        assertEquals(4, items.size());
      }
      case 6 -> {
        Map<String, Object> refs =
            (Map<String, Object>)
                dispatcher.dispatch(
                    "reference.list",
                    Map.of("filter", Map.of("direction", "to", "to", "ram:00010020")));
        List<?> items = (List<?>) refs.get("items");
        assertEquals(1, items.size());
      }
      case 7 -> {
        Map<String, Object> symbols =
            (Map<String, Object>)
                dispatcher.dispatch("symbol.list", Map.of("page", Map.of("limit", 20)));
        List<?> items = (List<?>) symbols.get("items");
        assertTrue(items.size() >= 2);
      }
      case 8 -> {
        String entry = (step % 2 == 0) ? "ram:00010000" : "ram:00010020";
        Map<String, Object> decomp =
            (Map<String, Object>)
                dispatcher.dispatch(
                    "decompilation.get", Map.of("selector", Map.of("entry", entry)));
        assertEquals(Boolean.TRUE, decomp.get("completed"));
        assertTrue(String.valueOf(decomp.get("c")).contains("return"));
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
                            Map.of("id", "prog", "method", "program.get", "arguments", Map.of()),
                            Map.of(
                                "id",
                                "dt",
                                "method",
                                "data_type.list",
                                "arguments",
                                Map.of("page", Map.of("limit", 5))),
                            Map.of(
                                "id",
                                "data",
                                "method",
                                "data_unit.list",
                                "arguments",
                                Map.of(
                                    "scan",
                                    Map.of(
                                        "range",
                                        Map.of(
                                            "start",
                                            "ram:00010040",
                                            "end",
                                            "ram:00010043")))))));
        List<?> items = (List<?>) batch.get("items");
        assertEquals(3, items.size());
      }
    }
  }

  private static void runWriteIteration(AgentDispatcher dispatcher, int writerId, int iter)
      throws Exception {
    switch ((writerId + iter) % 3) {
      case 0 ->
          dispatcher.dispatch(
              "comment.upsert",
              Map.of(
                  "resource",
                  Map.of(
                      "address", "ram:00010000",
                      "type", "eol",
                      "text", "COMMITTED_SINGLE_" + writerId + "_" + iter)));
      case 1 ->
          dispatcher.dispatch(
              "batch.execute",
              Map.of(
                  "transaction_mode",
                  "all_or_none",
                  "items",
                  List.of(
                      Map.of(
                          "id",
                          "c1",
                          "method",
                          "comment.upsert",
                          "arguments",
                          Map.of(
                              "resource",
                              Map.of(
                                  "address", "ram:00010000",
                                  "type", "eol",
                                  "text", "COMMITTED_BATCH_" + writerId + "_" + iter))),
                      Map.of(
                          "id",
                          "m1",
                          "method",
                          "memory.write",
                          "arguments",
                          Map.of(
                              "selector", Map.of("address", "ram:00010080"),
                              "patch",
                                  Map.of(
                                      "bytes",
                                      Map.of(
                                          "encoding", "hex",
                                          "data", String.format("%02x%02x", writerId, iter),
                                          "length", 2)))))));
      default -> {
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
                                        "selector", Map.of("entry", "ram:000100e0"),
                                        "patch", Map.of("name", "missing")))))));
        assertEquals(409, rolledBack.status());
        assertEquals("batch_rolled_back", rolledBack.error().code());
        assertEquals("missing-fn", rolledBack.error().details().get("failed_item"));
      }
    }
  }
}
