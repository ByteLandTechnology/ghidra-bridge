package app.byteland.ghidra.adapter.ghidra.memory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.adapter.ghidra.GhidraServiceFactory;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.GhidraTestSupport;
import app.byteland.ghidra.adapter.ghidra.GhidraTestSupport.ProgramHolder;
import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.memory.MemoryBlockConflictException;
import app.byteland.ghidra.service.memory.MemoryBlockResource;
import app.byteland.ghidra.service.memory.MemoryResource;
import app.byteland.ghidra.service.memory.MemoryService;
import app.byteland.ghidra.service.memory.MemoryService.MemoryBlockCreateRequest;
import app.byteland.ghidra.service.program.ProgramResource;
import ghidra.program.model.listing.Program;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class MemoryMutationsTest {
  @Test
  void createMemoryBlockPadsTrailingBytesWithFillByteOrZero() {
    try (ProgramHolder holder = GhidraTestSupport.createX64Program("memory-mutations-test")) {
      GhidraSession session = GhidraTestSupport.sessionFor(holder.program());
      MemoryService service = new MemoryServiceImpl(session);

      holder.inTransaction(
          program -> {
            MemoryBlockResource flash =
                service.createMemoryBlock(
                    new MemoryBlockCreateRequest(
                        "FLASH",
                        "0x08000000",
                        8L,
                        true,
                        0xFF,
                        new ByteSequence(ByteSequence.Encoding.HEX, "01020304", 4),
                        true,
                        false,
                        true,
                        false,
                        false,
                        "Erased flash tail"));
            assertTrue(flash.initialized());
            assertTrue(flash.execute());
            assertFalse(flash.write());
            assertEquals("Erased flash tail", flash.comment());

            MemoryBlockResource zeroTail =
                service.createMemoryBlock(
                    new MemoryBlockCreateRequest(
                        "ZERO_TAIL",
                        "0x08001000",
                        8L,
                        true,
                        null,
                        new ByteSequence(ByteSequence.Encoding.HEX, "aabbccdd", 4),
                        true,
                        true,
                        false,
                        false,
                        false,
                        null));
            assertTrue(zeroTail.initialized());

            MemoryBlockResource filledOnly =
                service.createMemoryBlock(
                    new MemoryBlockCreateRequest(
                        "FILLED_ONLY",
                        "0x08002000",
                        4L,
                        true,
                        0x5A,
                        null,
                        true,
                        true,
                        false,
                        false,
                        false,
                        null));
            assertTrue(filledOnly.initialized());
          });

      MemoryResource flashBytes =
          service.readMemoryRange("0x08000000", 8, ByteSequence.Encoding.HEX);
      assertEquals("01020304ffffffff", flashBytes.bytes().data());

      MemoryResource zeroTailBytes =
          service.readMemoryRange("0x08001000", 8, ByteSequence.Encoding.HEX);
      assertEquals("aabbccdd00000000", zeroTailBytes.bytes().data());

      MemoryResource filledOnlyBytes =
          service.readMemoryRange("0x08002000", 4, ByteSequence.Encoding.HEX);
      assertEquals("5a5a5a5a", filledOnlyBytes.bytes().data());
    }
  }

  @Test
  void createMemoryBlockRejectsDuplicateNamesAndOverlappingRanges() {
    try (ProgramHolder holder = GhidraTestSupport.createX64Program("memory-conflicts-test")) {
      GhidraSession session = GhidraTestSupport.sessionFor(holder.program());
      MemoryService service = new MemoryServiceImpl(session);

      holder.inTransaction(
          program -> {
            service.createMemoryBlock(
                new MemoryBlockCreateRequest(
                    "SRAM",
                    "0x20000000",
                    4096L,
                    false,
                    null,
                    null,
                    true,
                    true,
                    false,
                    true,
                    false,
                    null));

            MemoryBlockConflictException duplicate =
                assertThrows(
                    MemoryBlockConflictException.class,
                    () ->
                        service.createMemoryBlock(
                            new MemoryBlockCreateRequest(
                                "SRAM",
                                "0x30000000",
                                256L,
                                false,
                                null,
                                null,
                                true,
                                true,
                                false,
                                false,
                                false,
                                null)));
            assertEquals(409, duplicate.status());
            assertEquals("memory_block_exists", duplicate.code());

            MemoryBlockConflictException overlap =
                assertThrows(
                    MemoryBlockConflictException.class,
                    () ->
                        service.createMemoryBlock(
                            new MemoryBlockCreateRequest(
                                "SRAM_SUB",
                                "0x20000800",
                                256L,
                                false,
                                null,
                                null,
                                true,
                                true,
                                false,
                                false,
                                false,
                                null)));
            assertEquals(409, overlap.status());
            assertEquals("memory_block_conflict", overlap.code());
          });
    }
  }

  @Test
  void rebaseAndCreateMemoryBlockFollowActiveProgramSwitch() {
    try (ProgramHolder alphaHolder = GhidraTestSupport.createX64Program("alpha.bin");
        ProgramHolder betaHolder = GhidraTestSupport.createX64Program("beta.bin")) {
      AtomicReference<Program> active = new AtomicReference<>(alphaHolder.program());
      GhidraSession session = new GhidraSession(active::get);
      try (var services = GhidraServiceFactory.create(session, "fallback.bin")) {
        services
            .transactionRunner()
            .run(
                () -> {
                  services
                      .memoryService()
                      .createMemoryBlock(
                          new MemoryBlockCreateRequest(
                              "ALPHA_SRAM",
                              "0x20000000",
                              256L,
                              false,
                              null,
                              null,
                              true,
                              true,
                              false,
                              false,
                              false,
                              null));
                  ProgramResource rebasedAlpha =
                      services.programService().rebaseProgram("0x08000000");
                  assertEquals("alpha.bin", rebasedAlpha.name());
                  assertTrue(rebasedAlpha.imageBase().endsWith("08000000"));
                  return null;
                });

        active.set(betaHolder.program());
        services
            .transactionRunner()
            .run(
                () -> {
                  services
                      .memoryService()
                      .createMemoryBlock(
                          new MemoryBlockCreateRequest(
                              "BETA_SRAM",
                              "0x30000000",
                              512L,
                              false,
                              null,
                              null,
                              true,
                              true,
                              false,
                              true,
                              false,
                              null));
                  ProgramResource rebasedBeta =
                      services.programService().rebaseProgram("0x10000000");
                  assertEquals("beta.bin", rebasedBeta.name());
                  assertTrue(rebasedBeta.imageBase().endsWith("10000000"));
                  return null;
                });

        assertEquals(0x08000000L, alphaHolder.program().getImageBase().getOffset());
        assertEquals(0x10000000L, betaHolder.program().getImageBase().getOffset());
        assertTrue(alphaHolder.program().getMemory().getBlock("ALPHA_SRAM") != null);
        assertTrue(alphaHolder.program().getMemory().getBlock("BETA_SRAM") == null);
        assertTrue(betaHolder.program().getMemory().getBlock("BETA_SRAM") != null);
        assertTrue(betaHolder.program().getMemory().getBlock("ALPHA_SRAM") == null);
      }
    }
  }
}
