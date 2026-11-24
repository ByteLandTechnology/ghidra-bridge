package app.byteland.ghidra.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.TransactionRunner;
import app.byteland.ghidra.service.address.AddressService;
import app.byteland.ghidra.service.analysis.AnalysisResource;
import app.byteland.ghidra.service.analysis.AnalysisService;
import app.byteland.ghidra.service.comment.CommentService;
import app.byteland.ghidra.service.datatype.DataTypeService;
import app.byteland.ghidra.service.decompilation.DecompilationService;
import app.byteland.ghidra.service.function.FunctionService;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService;
import app.byteland.ghidra.service.listing.ListingService;
import app.byteland.ghidra.service.memory.MemoryBlockConflictException;
import app.byteland.ghidra.service.memory.MemoryBlockResource;
import app.byteland.ghidra.service.memory.MemoryService;
import app.byteland.ghidra.service.memory.MemoryService.MemoryBlockCreateRequest;
import app.byteland.ghidra.service.program.ProgramConflictException;
import app.byteland.ghidra.service.program.ProgramResource;
import app.byteland.ghidra.service.program.ProgramService;
import app.byteland.ghidra.service.reference.ReferenceService;
import app.byteland.ghidra.service.symbol.SymbolService;
import java.lang.reflect.Proxy;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class ProgramAndMemoryMutationTest {
  @Test
  void rebaseAndMemoryBlockCreateValidateAndComposeInBatch() throws Exception {
    AtomicReference<String> imageBase = new AtomicReference<>("ram:00000000");
    List<MemoryBlockCreateRequest> createdBlocks = new ArrayList<>();
    AtomicBoolean analysisRunning = new AtomicBoolean(false);
    AtomicInteger transactions = new AtomicInteger();

    ProgramService programs =
        proxy(
            ProgramService.class,
            (method, args) -> {
              if ("rebaseProgram".equals(method)) {
                String requested = String.valueOf(args[0]);
                if ("0xffffffff".equals(requested)) {
                  throw new ProgramConflictException(
                      "address_overflow", "/image_base", "image base overflows address space");
                }
                imageBase.set("ram:" + requested.replace("0x", ""));
              }
              return new ProgramResource(
                  "firmware.bin",
                  "/tmp/firmware.bin",
                  "Raw Binary",
                  imageBase.get(),
                  imageBase.get(),
                  "ram:08000fff",
                  "ARM:LE:32:Cortex",
                  "default",
                  Instant.EPOCH,
                  Instant.EPOCH,
                  2L,
                  5L);
            });

    MemoryService memory =
        proxy(
            MemoryService.class,
            (method, args) -> {
              assertEquals("createMemoryBlock", method);
              MemoryBlockCreateRequest req = (MemoryBlockCreateRequest) args[0];
              if ("OVERLAP".equals(req.name())) {
                throw new MemoryBlockConflictException(
                    "memory_block_conflict", "/resource/start", "memory block overlaps range");
              }
              createdBlocks.add(req);
              return new MemoryBlockResource(
                  req.name(),
                  "ram:" + req.start().replace("0x", ""),
                  "ram:2000ffff",
                  req.length(),
                  req.read(),
                  req.write(),
                  req.execute(),
                  req.initialized(),
                  req.isVolatile(),
                  req.overlay(),
                  MemoryBlockResource.Kind.DEFAULT,
                  req.comment());
            });

    AnalysisService analysis =
        proxy(
            AnalysisService.class,
            (method, args) ->
                new AnalysisResource(
                    AnalysisResource.Kind.GHIDRA,
                    analysisRunning.get()
                        ? AnalysisResource.Status.RUNNING
                        : AnalysisResource.Status.IDLE,
                    false,
                    null,
                    null,
                    null,
                    null));

    TransactionRunner transaction =
        new TransactionRunner() {
          @Override
          public <T> T run(Operation<T> operation) {
            transactions.incrementAndGet();
            String snapshotBase = imageBase.get();
            int snapshotBlocks = createdBlocks.size();
            try {
              return operation.execute();
            } catch (RuntimeException ex) {
              imageBase.set(snapshotBase);
              while (createdBlocks.size() > snapshotBlocks) {
                createdBlocks.removeLast();
              }
              throw ex;
            } catch (Exception ex) {
              imageBase.set(snapshotBase);
              while (createdBlocks.size() > snapshotBlocks) {
                createdBlocks.removeLast();
              }
              throw new RuntimeException(ex);
            }
          }
        };

    BridgeServices services =
        new BridgeServices(
            programs,
            unused(AddressService.class),
            unused(CommentService.class),
            unused(ReferenceService.class),
            memory,
            unused(ListingService.class),
            unused(FunctionService.class),
            unused(GlobalVariableService.class),
            analysis,
            unused(DecompilationService.class),
            unused(SymbolService.class),
            unused(DataTypeService.class),
            transaction,
            "test");
    ApiRegistry registry = new ApiRegistry(services, "test", Map::of, () -> {});

    assertTrue(registry.method("program.rebase").effects().requiresTransaction());
    assertFalse(registry.method("program.rebase").effects().allowedDuringAnalysis());
    assertTrue(registry.method("program.rebase").effects().batchable());
    assertTrue(registry.method("memory_block.create").effects().requiresTransaction());
    assertFalse(registry.method("memory_block.create").effects().allowedDuringAnalysis());
    assertTrue(registry.method("memory_block.create").effects().batchable());

    Map<?, ?> rebased =
        (Map<?, ?>) registry.dispatch("program.rebase", Map.of("image_base", "0x08000000"));
    assertEquals("ram:08000000", rebased.get("image_base"));
    assertEquals(1, transactions.get());

    ProgramConflictException overflow =
        assertThrows(
            ProgramConflictException.class,
            () -> registry.dispatch("program.rebase", Map.of("image_base", "0xffffffff")));
    assertEquals(409, overflow.status());

    Map<String, Object> mmioResource = new LinkedHashMap<>();
    mmioResource.put("name", "PERIPH");
    mmioResource.put("start", "0x40000000");
    mmioResource.put("length", 4096);
    mmioResource.put("read", true);
    mmioResource.put("write", true);
    mmioResource.put("execute", false);
    mmioResource.put("is_volatile", true);
    mmioResource.put("overlay", false);
    mmioResource.put("comment", "Peripheral registers");
    Map<?, ?> createdMmio =
        (Map<?, ?>) registry.dispatch("memory_block.create", Map.of("resource", mmioResource));
    assertEquals("PERIPH", createdMmio.get("name"));
    assertEquals(Boolean.FALSE, createdMmio.get("initialized"));
    assertEquals(Boolean.TRUE, createdMmio.get("volatile"));
    assertEquals("Peripheral registers", createdMmio.get("comment"));

    Map<String, Object> initResource =
        Map.of(
            "name",
            "VECTORS",
            "start",
            "0x08000000",
            "length",
            8,
            "bytes",
            Map.of("encoding", "hex", "data", "00200020", "length", 4),
            "fill_byte",
            0xFF,
            "read",
            true,
            "write",
            false,
            "execute",
            true);
    Map<?, ?> createdInit =
        (Map<?, ?>) registry.dispatch("memory_block.create", Map.of("resource", initResource));
    assertEquals(Boolean.TRUE, createdInit.get("initialized"));
    assertEquals(ByteSequence.Encoding.HEX, createdBlocks.getLast().bytes().encoding());
    assertEquals(0xFF, createdBlocks.getLast().fillByte());

    Map<?, ?> exactMaxInit =
        (Map<?, ?>)
            registry.dispatch(
                "memory_block.create",
                Map.of(
                    "resource",
                    Map.of(
                        "name",
                        "MAX_FLASH",
                        "start",
                        "0x10000000",
                        "length",
                        MemoryService.MAX_INITIALIZED_BLOCK_LENGTH,
                        "initialized",
                        true)));
    assertEquals(Boolean.TRUE, exactMaxInit.get("initialized"));
    assertEquals(
        (long) MemoryService.MAX_INITIALIZED_BLOCK_LENGTH,
        ((Number) exactMaxInit.get("length")).longValue());

    Map<?, ?> largeUninit =
        (Map<?, ?>)
            registry.dispatch(
                "memory_block.create",
                Map.of(
                    "resource",
                    Map.of(
                        "name",
                        "DRAM",
                        "start",
                        "0x80000000",
                        "length",
                        MemoryService.MAX_INITIALIZED_BLOCK_LENGTH + 4096L)));
    assertEquals(Boolean.FALSE, largeUninit.get("initialized"));

    ApiException oversizedInit =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "memory_block.create",
                    Map.of(
                        "resource",
                        Map.of(
                            "name",
                            "TOO_BIG_INIT",
                            "start",
                            "0x10000000",
                            "length",
                            MemoryService.MAX_INITIALIZED_BLOCK_LENGTH + 1L,
                            "initialized",
                            true))));
    assertEquals(400, oversizedInit.status());
    assertEquals("invalid_value", oversizedInit.error().code());
    assertEquals("/resource/length", oversizedInit.error().target());

    ApiException oversizedFillInit =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "memory_block.create",
                    Map.of(
                        "resource",
                        Map.of(
                            "name",
                            "TOO_BIG_FILL",
                            "start",
                            "0x10000000",
                            "length",
                            MemoryService.MAX_INITIALIZED_BLOCK_LENGTH + 1L,
                            "fill_byte",
                            0xFF))));
    assertEquals(400, oversizedFillInit.status());
    assertEquals("invalid_value", oversizedFillInit.error().code());
    assertEquals("/resource/length", oversizedFillInit.error().target());

    ApiException oversizedBlock =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "memory_block.create",
                    Map.of(
                        "resource",
                        Map.of(
                            "name",
                            "TOO_BIG_UNINIT",
                            "start",
                            "0x10000000",
                            "length",
                            MemoryService.MAX_BLOCK_LENGTH + 1L))));
    assertEquals(400, oversizedBlock.status());
    assertEquals("invalid_value", oversizedBlock.error().code());
    assertEquals("/resource/length", oversizedBlock.error().target());

    assertThrows(
        ApiException.class,
        () ->
            registry.dispatch(
                "memory_block.create",
                Map.of(
                    "resource",
                    Map.of(
                        "name",
                        "BAD",
                        "start",
                        "0x20000000",
                        "length",
                        4,
                        "initialized",
                        false,
                        "fill_byte",
                        0))));

    analysisRunning.set(true);
    ApiException busyRebase =
        assertThrows(
            ApiException.class,
            () -> registry.dispatch("program.rebase", Map.of("image_base", "0x08001000")));
    assertEquals(409, busyRebase.status());
    ApiException busyBatch =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "batch.execute",
                    Map.of(
                        "transaction_mode",
                        "all_or_none",
                        "items",
                        List.of(
                            Map.of(
                                "id",
                                "1",
                                "method",
                                "program.rebase",
                                "arguments",
                                Map.of("image_base", "0x08001000"))))));
    assertEquals(409, busyBatch.status());
    analysisRunning.set(false);

    int blocksBeforeRollback = createdBlocks.size();
    ApiException atomicFailed =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "batch.execute",
                    Map.of(
                        "transaction_mode",
                        "all_or_none",
                        "items",
                        List.of(
                            Map.of(
                                "id",
                                "rebase",
                                "method",
                                "program.rebase",
                                "arguments",
                                Map.of("image_base", "0x08010000")),
                            Map.of(
                                "id",
                                "overlap",
                                "method",
                                "memory_block.create",
                                "arguments",
                                Map.of(
                                    "resource",
                                    Map.of(
                                        "name",
                                        "OVERLAP",
                                        "start",
                                        "0x08010000",
                                        "length",
                                        256)))))));
    assertEquals(409, atomicFailed.status());
    assertEquals("batch_rolled_back", atomicFailed.error().code());
    assertEquals("overlap", atomicFailed.error().details().get("failed_item"));
    assertEquals("ram:08000000", imageBase.get());
    assertEquals(blocksBeforeRollback, createdBlocks.size());

    Map<?, ?> perItemResult =
        (Map<?, ?>)
            registry.dispatch(
                "batch.execute",
                Map.of(
                    "transaction_mode",
                    "per_item",
                    "items",
                    List.of(
                        Map.of(
                            "id",
                            "rebase",
                            "method",
                            "program.rebase",
                            "arguments",
                            Map.of("image_base", "0x08020000")),
                        Map.of(
                            "id",
                            "sram",
                            "method",
                            "memory_block.create",
                            "arguments",
                            Map.of(
                                "resource",
                                Map.of("name", "SRAM", "start", "0x20000000", "length", 65536))),
                        Map.of(
                            "id",
                            "overlap",
                            "method",
                            "memory_block.create",
                            "arguments",
                            Map.of(
                                "resource",
                                Map.of(
                                    "name", "OVERLAP", "start", "0x20000000", "length", 256))))));
    assertEquals("ram:08020000", imageBase.get());
    assertEquals("SRAM", createdBlocks.getLast().name());
    List<?> perItems = (List<?>) perItemResult.get("items");
    assertTrue(((Map<?, ?>) perItems.get(0)).containsKey("result"));
    assertTrue(((Map<?, ?>) perItems.get(1)).containsKey("result"));
    assertTrue(((Map<?, ?>) perItems.get(2)).containsKey("error"));
  }

  private interface Handler {
    Object invoke(String method, Object[] args);
  }

  private static <T> T unused(Class<T> type) {
    return proxy(
        type,
        (method, args) -> {
          throw new AssertionError(method);
        });
  }

  private static <T> T proxy(Class<T> type, Handler handler) {
    return type.cast(
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (proxy, method, args) -> handler.invoke(method.getName(), args)));
  }
}
