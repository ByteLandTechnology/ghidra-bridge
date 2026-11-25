package app.byteland.ghidra.adapter.ghidra.listing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.adapter.ghidra.GhidraTestSupport;
import app.byteland.ghidra.adapter.ghidra.GhidraTestSupport.ProgramHolder;
import app.byteland.ghidra.adapter.ghidra.GhidraTestSupport.SeekSpy;
import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.ScanProgress;
import app.byteland.ghidra.service.listing.CodeUnitResource;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DWordDataType;
import ghidra.util.task.TaskMonitor;
import java.io.ByteArrayInputStream;
import java.util.List;
import org.junit.jupiter.api.Test;

class ListingCodeUnitQueriesTest {

  @Test
  void allKindStreamsForwardWithStatefulCodeUnitIterator() {
    try (ProgramHolder holder = GhidraTestSupport.createX64Program("code_units_all")) {
      holder.inTransaction(program -> {
        Address base = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000L);
        // 0x1000..0x1004: mov eax, 0x11223344 (5 bytes)
        // 0x1005: undefined (1 byte)
        // 0x1006..0x1009: dword (4 bytes)
        // 0x100a: ret (1 byte)
        byte[] bytes = {
          (byte) 0xb8, 0x44, 0x33, 0x22, 0x11, 0x00, 0x78, 0x56, 0x34, 0x12, (byte) 0xc3
        };
        program
            .getMemory()
            .createInitializedBlock(
                ".text",
                base,
                new ByteArrayInputStream(bytes),
                bytes.length,
                TaskMonitor.DUMMY,
                false);
        new DisassembleCommand(base, new AddressSet(base, base.add(4)), false)
            .applyTo(program, TaskMonitor.DUMMY);
        program.getListing().createData(base.add(6), DWordDataType.dataType);
        Address retAddr = base.add(10);
        new DisassembleCommand(retAddr, new AddressSet(retAddr, retAddr), false)
            .applyTo(program, TaskMonitor.DUMMY);
      });

      SeekSpy spy = new SeekSpy();
      ListingCodeUnitQueries queries =
          new ListingCodeUnitQueries(GhidraTestSupport.sessionFor(spy.wrap(holder.program())));

      Page<CodeUnitResource> forward =
          queries.listCodeUnits(
              AddressScanOptions.of("ram:00001000", "ram:0000100a", 1000), 10, "all", null);
      assertEquals(1, spy.codeUnitIterators.get());
      assertEquals(0, spy.statelessAfterBeforeCalls.get());
      assertEquals(
          List.of("ram:00001000", "ram:00001005", "ram:00001006", "ram:0000100a"),
          forward.items().stream().map(CodeUnitResource::address).toList());
      assertEquals(
          List.of(
              CodeUnitResource.Kind.INSTRUCTION,
              CodeUnitResource.Kind.UNDEFINED,
              CodeUnitResource.Kind.DATA,
              CodeUnitResource.Kind.INSTRUCTION),
          forward.items().stream().map(CodeUnitResource::kind).toList());
      assertEquals("ram:00001000", forward.scanProgress().scannedStart());
      assertEquals("ram:0000100a", forward.scanProgress().scannedEnd());
      assertTrue(forward.scanProgress().complete());
      assertNull(forward.nextCursor());
    }
  }

  @Test
  void filteredInstructionAndDataScansSkip64KbUndefinedGapAndPreserveScanBounds() {
    try (ProgramHolder holder = GhidraTestSupport.createX64Program("code_units_gap")) {
      holder.inTransaction(program -> {
        Address base = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x100000L);
        // 0x100000..0x10ffff: 64 KB undefined gap
        // 0x110000: nop (1 byte)
        // 0x110001: ret (1 byte)
        // 0x110008..0x11000b: dword (4 bytes)
        // 0x11000c..0x11001f: undefined tail
        byte[] bytes = new byte[0x10020];
        bytes[0x10000] = (byte) 0x90;
        bytes[0x10001] = (byte) 0xc3;
        program
            .getMemory()
            .createInitializedBlock(
                ".bss_and_text",
                base,
                new ByteArrayInputStream(bytes),
                bytes.length,
                TaskMonitor.DUMMY,
                false);
        Address instStart = base.add(0x10000);
        AddressSet instSet = new AddressSet(instStart, instStart.add(1));
        new DisassembleCommand(instSet, instSet, false).applyTo(program, TaskMonitor.DUMMY);
        program.getListing().createData(base.add(0x10008), DWordDataType.dataType);
      });

      SeekSpy spy = new SeekSpy();
      ListingCodeUnitQueries queries =
          new ListingCodeUnitQueries(GhidraTestSupport.sessionFor(spy.wrap(holder.program())));

      // Completed instruction scan across 64 KB undefined gap and final undefined tail
      Page<CodeUnitResource> instructions =
          queries.listCodeUnits(
              AddressScanOptions.of("ram:00100000", "ram:0011001f", 100), 10, "instruction", null);
      assertEquals(1, spy.instructionIterators.get());
      assertEquals(0, spy.codeUnitIterators.get());
      assertEquals(0, spy.statelessAfterBeforeCalls.get());
      assertTrue(spy.boundaryLookups.get() <= 2);
      assertEquals(
          List.of("ram:00110000", "ram:00110001"),
          instructions.items().stream().map(CodeUnitResource::address).toList());
      assertEquals("ram:00100000", instructions.scanProgress().scannedStart());
      assertEquals("ram:0011001f", instructions.scanProgress().scannedEnd());
      assertTrue(instructions.scanProgress().complete());
      assertEquals(ScanProgress.StopReason.COMPLETED, instructions.scanProgress().stopReason());
      assertNull(instructions.nextCursor());

      // Paginated instruction scan (limit = 1) + cursor resume
      spy.reset();
      Page<CodeUnitResource> page1 =
          queries.listCodeUnits(
              AddressScanOptions.of("ram:00100000", "ram:0011001f", 100), 1, "instruction", null);
      assertEquals(1, spy.instructionIterators.get());
      assertEquals(1, spy.boundaryLookups.get());
      assertEquals(
          List.of("ram:00110000"), page1.items().stream().map(CodeUnitResource::address).toList());
      assertEquals("ram:00100000", page1.scanProgress().scannedStart());
      assertEquals("ram:00110000", page1.scanProgress().scannedEnd());
      assertFalse(page1.scanProgress().complete());
      assertEquals(ScanProgress.StopReason.LIMIT, page1.scanProgress().stopReason());
      assertEquals("ram:00110000", page1.nextCursor());

      spy.reset();
      Page<CodeUnitResource> page2 =
          queries.listCodeUnits(
              AddressScanOptions.of("ram:00100000", "ram:0011001f", 100),
              10,
              "instruction",
              page1.nextCursor());
      assertEquals(1, spy.instructionIterators.get());
      assertTrue(spy.boundaryLookups.get() <= 2);
      assertEquals(
          List.of("ram:00110001"), page2.items().stream().map(CodeUnitResource::address).toList());
      assertEquals("ram:00110001", page2.scanProgress().scannedStart());
      assertEquals("ram:0011001f", page2.scanProgress().scannedEnd());
      assertTrue(page2.scanProgress().complete());
      assertNull(page2.nextCursor());

      // Completed defined data scan across 64 KB undefined gap
      spy.reset();
      Page<CodeUnitResource> dataUnits =
          queries.listCodeUnits(
              AddressScanOptions.of("ram:00100000", "ram:0011001f", 100), 10, "data", null);
      assertEquals(1, spy.definedDataIterators.get());
      assertEquals(0, spy.codeUnitIterators.get());
      assertEquals(0, spy.statelessAfterBeforeCalls.get());
      assertTrue(spy.boundaryLookups.get() <= 2);
      assertEquals(
          List.of("ram:00110008"),
          dataUnits.items().stream().map(CodeUnitResource::address).toList());
      assertEquals("ram:00100000", dataUnits.scanProgress().scannedStart());
      assertEquals("ram:0011001f", dataUnits.scanProgress().scannedEnd());
      assertTrue(dataUnits.scanProgress().complete());
      assertNull(dataUnits.nextCursor());

      // Pure 64 KB undefined gap with zero matches still anchors scannedStart and scannedEnd
      spy.reset();
      Page<CodeUnitResource> emptyGap =
          queries.listCodeUnits(
              AddressScanOptions.of("ram:00100000", "ram:0010ffff", 100), 10, "instruction", null);
      assertEquals(1, spy.instructionIterators.get());
      assertTrue(spy.boundaryLookups.get() <= 2);
      assertTrue(emptyGap.items().isEmpty());
      assertEquals("ram:00100000", emptyGap.scanProgress().scannedStart());
      assertEquals("ram:0010ffff", emptyGap.scanProgress().scannedEnd());
      assertTrue(emptyGap.scanProgress().complete());
      assertNull(emptyGap.nextCursor());
    }
  }

  @Test
  void multiByteBoundariesAndAddressSpaceExtremesNeverOverflow() {
    try (ProgramHolder holder = GhidraTestSupport.createX64Program("code_units_boundaries")) {
      holder.inTransaction(program -> {
        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
        Address minBlock = space.getMinAddress();
        byte[] lowBytes = {(byte) 0x90, (byte) 0xc3};
        program
            .getMemory()
            .createInitializedBlock(
                ".low",
                minBlock,
                new ByteArrayInputStream(lowBytes),
                lowBytes.length,
                TaskMonitor.DUMMY,
                false);
        AddressSet lowSet = new AddressSet(minBlock, minBlock.add(1));
        new DisassembleCommand(lowSet, lowSet, false).applyTo(program, TaskMonitor.DUMMY);

        // Multi-byte block at 0x2000:
        // 0x2000..0x2004: 5-byte mov eax, imm32
        // 0x2005..0x2008: 4-byte dword
        Address mid = space.getAddress(0x2000L);
        byte[] midBytes = {(byte) 0xb8, 1, 2, 3, 4, 9, 8, 7, 6};
        program
            .getMemory()
            .createInitializedBlock(
                ".mid",
                mid,
                new ByteArrayInputStream(midBytes),
                midBytes.length,
                TaskMonitor.DUMMY,
                false);
        new DisassembleCommand(mid, new AddressSet(mid, mid.add(4)), false)
            .applyTo(program, TaskMonitor.DUMMY);
        program.getListing().createData(mid.add(5), DWordDataType.dataType);

        Address highStart = space.getMaxAddress().subtract(1);
        byte[] highBytes = {(byte) 0x90, (byte) 0xc3};
        program
            .getMemory()
            .createInitializedBlock(
                ".high",
                highStart,
                new ByteArrayInputStream(highBytes),
                highBytes.length,
                TaskMonitor.DUMMY,
                false);
        AddressSet highSet = new AddressSet(highStart, space.getMaxAddress());
        new DisassembleCommand(highSet, highSet, false).applyTo(program, TaskMonitor.DUMMY);
      });

      ListingCodeUnitQueries queries =
          new ListingCodeUnitQueries(GhidraTestSupport.sessionFor(holder.program()));

      // Start inside 5-byte instruction (0x2002) skips 0x2000 and starts at 0x2005
      Page<CodeUnitResource> midForward =
          queries.listCodeUnits(
              AddressScanOptions.of("ram:00002002", "ram:00002007", 1000), 10, "data", null);
      assertEquals(
          List.of("ram:00002005"),
          midForward.items().stream().map(CodeUnitResource::address).toList());
      assertEquals("ram:00002005", midForward.scanProgress().scannedStart());
      assertEquals("ram:00002005", midForward.scanProgress().scannedEnd());

      // Interior slice [0x2001, 0x2003] inside 5-byte instruction has no code unit starts
      Page<CodeUnitResource> interiorSlice =
          queries.listCodeUnits(
              AddressScanOptions.of("ram:00002001", "ram:00002003", 1000), 10, "instruction", null);
      assertTrue(interiorSlice.items().isEmpty());
      assertNull(interiorSlice.scanProgress().scannedStart());
      assertNull(interiorSlice.scanProgress().scannedEnd());
      assertTrue(interiorSlice.scanProgress().complete());

      // Cursor resumption at maxAddress (0xffffffffffffffff) for all kinds
      for (String kind : List.of("all", "instruction", "data")) {
        Page<CodeUnitResource> atMax =
            queries.listCodeUnits(
                AddressScanOptions.of("ram:fffffffffffffffe", "ram:ffffffffffffffff", 1000),
                10,
                kind,
                "ram:ffffffffffffffff");
        assertTrue(atMax.items().isEmpty());
        assertTrue(atMax.scanProgress().complete());
        assertNull(atMax.scanProgress().scannedStart());
        assertNull(atMax.scanProgress().scannedEnd());
        assertNull(atMax.nextCursor());
      }
    }
  }
}
