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
import app.byteland.ghidra.service.listing.DataUnitResource;
import app.byteland.ghidra.service.listing.InstructionResource;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.util.task.TaskMonitor;
import java.io.ByteArrayInputStream;
import java.util.List;
import org.junit.jupiter.api.Test;

class ListingInstructionAndDataQueriesTest {

  @Test
  void instructionQueriesStreamForwardAndBackwardAndResumeAtMaxAddress() {
    try (ProgramHolder holder = GhidraTestSupport.createX64Program("instructions_test")) {
      holder.inTransaction(program -> {
        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
        Address minAddr = space.getMinAddress();
        byte[] lowBytes = {(byte) 0xc3};
        program
            .getMemory()
            .createInitializedBlock(
                ".low",
                minAddr,
                new ByteArrayInputStream(lowBytes),
                lowBytes.length,
                TaskMonitor.DUMMY,
                false);
        new DisassembleCommand(minAddr, new AddressSet(minAddr, minAddr), false)
            .applyTo(program, TaskMonitor.DUMMY);

        // 0x3000..0x3004: mov eax, imm32 (5 bytes)
        // 0x3005: nop (1 byte)
        // 0x3006: ret (1 byte)
        Address base = space.getAddress(0x3000L);
        byte[] body = {(byte) 0xb8, 0x01, 0x00, 0x00, 0x00, (byte) 0x90, (byte) 0xc3};
        program
            .getMemory()
            .createInitializedBlock(
                ".text",
                base,
                new ByteArrayInputStream(body),
                body.length,
                TaskMonitor.DUMMY,
                false);
        AddressSet bodySet = new AddressSet(base, base.add(6));
        new DisassembleCommand(bodySet, bodySet, false).applyTo(program, TaskMonitor.DUMMY);

        Address maxAddr = space.getMaxAddress();
        byte[] highBytes = {(byte) 0xc3};
        program
            .getMemory()
            .createInitializedBlock(
                ".high",
                maxAddr,
                new ByteArrayInputStream(highBytes),
                highBytes.length,
                TaskMonitor.DUMMY,
                false);
        new DisassembleCommand(maxAddr, new AddressSet(maxAddr, maxAddr), false)
            .applyTo(program, TaskMonitor.DUMMY);
      });

      SeekSpy spy = new SeekSpy();
      ListingInstructionQueries queries =
          new ListingInstructionQueries(GhidraTestSupport.sessionFor(spy.wrap(holder.program())));

      // Forward pagination with inclusive bounds
      Page<InstructionResource> page1 =
          queries.listInstructions(
              AddressScanOptions.of("ram:00003000", "ram:00003006", 1000), 2, "forward", null);
      assertEquals(1, spy.instructionIterators.get());
      assertEquals(0, spy.statelessAfterBeforeCalls.get());
      assertEquals(
          List.of("ram:00003000", "ram:00003005"),
          page1.items().stream().map(InstructionResource::address).toList());
      assertEquals("ram:00003005", page1.nextCursor());
      assertEquals(ScanProgress.StopReason.LIMIT, page1.scanProgress().stopReason());

      spy.reset();
      Page<InstructionResource> page2 =
          queries.listInstructions(
              AddressScanOptions.of("ram:00003000", "ram:00003006", 1000),
              2,
              "forward",
              page1.nextCursor());
      assertEquals(1, spy.instructionIterators.get());
      assertEquals(0, spy.statelessAfterBeforeCalls.get());
      assertEquals(
          List.of("ram:00003006"),
          page2.items().stream().map(InstructionResource::address).toList());
      assertTrue(page2.scanProgress().complete());
      assertNull(page2.nextCursor());

      // Backward scan + cursor resumption + multi-byte start/end bounds
      spy.reset();
      Page<InstructionResource> backPage1 =
          queries.listInstructions(
              AddressScanOptions.of("ram:00003000", "ram:00003006", 1000), 2, "backward", null);
      assertEquals(1, spy.instructionIterators.get());
      assertEquals(0, spy.statelessAfterBeforeCalls.get());
      assertEquals(
          List.of("ram:00003006", "ram:00003005"),
          backPage1.items().stream().map(InstructionResource::address).toList());
      assertEquals("ram:00003006", backPage1.scanProgress().scannedStart());
      assertEquals("ram:00003005", backPage1.scanProgress().scannedEnd());

      Page<InstructionResource> backPage2 =
          queries.listInstructions(
              AddressScanOptions.of("ram:00003000", "ram:00003006", 1000),
              2,
              "backward",
              backPage1.nextCursor());
      assertEquals(
          List.of("ram:00003000"),
          backPage2.items().stream().map(InstructionResource::address).toList());
      assertTrue(backPage2.scanProgress().complete());

      // Multi-byte boundary: start inside 5-byte instruction (0x3002) excludes 0x3000;
      // end inside 5-byte instruction (0x3003) includes 0x3000.
      Page<InstructionResource> startMid =
          queries.listInstructions(
              AddressScanOptions.of("ram:00003002", "ram:00003006", 1000), 10, "forward", null);
      assertEquals(
          List.of("ram:00003005", "ram:00003006"),
          startMid.items().stream().map(InstructionResource::address).toList());

      Page<InstructionResource> endMid =
          queries.listInstructions(
              AddressScanOptions.of("ram:00003000", "ram:00003003", 1000), 10, "backward", null);
      assertEquals(
          List.of("ram:00003000"),
          endMid.items().stream().map(InstructionResource::address).toList());

      // Cursor resumption at maxAddress and minAddress with live instructions at those extremes
      spy.reset();
      Page<InstructionResource> resumeAtMax =
          queries.listInstructions(
              AddressScanOptions.of("ram:00003000", "ram:ffffffffffffffff", 1000),
              10,
              "forward",
              "ram:ffffffffffffffff");
      assertEquals(1, spy.instructionIterators.get());
      assertTrue(resumeAtMax.items().isEmpty());
      assertTrue(resumeAtMax.scanProgress().complete());
      assertNull(resumeAtMax.nextCursor());

      Page<InstructionResource> resumeAtMin =
          queries.listInstructions(
              AddressScanOptions.of("ram:0000000000000000", "ram:00003006", 1000),
              10,
              "backward",
              "ram:0000000000000000");
      assertTrue(resumeAtMin.items().isEmpty());
      assertTrue(resumeAtMin.scanProgress().complete());
    }
  }

  @Test
  void dataQueriesStreamForwardAndBackwardAndResumeAtMaxAddress() {
    try (ProgramHolder holder = GhidraTestSupport.createX64Program("data_units_test")) {
      holder.inTransaction(program -> {
        AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
        Address minAddr = space.getMinAddress();
        program
            .getMemory()
            .createInitializedBlock(
                ".low",
                minAddr,
                new ByteArrayInputStream(new byte[] {0x11}),
                1,
                TaskMonitor.DUMMY,
                false);
        program.getListing().createData(minAddr, ByteDataType.dataType);

        // 0x4000..0x4003: dword (4 bytes)
        // 0x4008..0x4009: word (2 bytes)
        // 0x4010: byte (1 byte)
        Address base = space.getAddress(0x4000L);
        byte[] bytes = new byte[0x20];
        bytes[0] = 1;
        bytes[8] = 2;
        bytes[0x10] = 3;
        program
            .getMemory()
            .createInitializedBlock(
                ".data",
                base,
                new ByteArrayInputStream(bytes),
                bytes.length,
                TaskMonitor.DUMMY,
                false);
        program.getListing().createData(base, DWordDataType.dataType);
        program.getListing().createData(base.add(8), WordDataType.dataType);
        program.getListing().createData(base.add(0x10), ByteDataType.dataType);

        Address maxAddr = space.getMaxAddress();
        program
            .getMemory()
            .createInitializedBlock(
                ".high",
                maxAddr,
                new ByteArrayInputStream(new byte[] {0x7f}),
                1,
                TaskMonitor.DUMMY,
                false);
        program.getListing().createData(maxAddr, ByteDataType.dataType);
      });

      SeekSpy spy = new SeekSpy();
      ListingDataQueries queries =
          new ListingDataQueries(GhidraTestSupport.sessionFor(spy.wrap(holder.program())));

      // Forward pagination
      Page<DataUnitResource> page1 =
          queries.listDataUnits(
              AddressScanOptions.of("ram:00004000", "ram:00004010", 1000), 2, "forward", null);
      assertEquals(1, spy.definedDataIterators.get());
      assertEquals(0, spy.statelessAfterBeforeCalls.get());
      assertEquals(
          List.of("ram:00004000", "ram:00004008"),
          page1.items().stream().map(DataUnitResource::address).toList());
      assertFalse(page1.scanProgress().complete());
      assertEquals("ram:00004008", page1.nextCursor());

      spy.reset();
      Page<DataUnitResource> page2 =
          queries.listDataUnits(
              AddressScanOptions.of("ram:00004000", "ram:00004010", 1000),
              2,
              "forward",
              page1.nextCursor());
      assertEquals(1, spy.definedDataIterators.get());
      assertEquals(0, spy.statelessAfterBeforeCalls.get());
      assertEquals(
          List.of("ram:00004010"), page2.items().stream().map(DataUnitResource::address).toList());
      assertTrue(page2.scanProgress().complete());

      // Backward scan + cursor resumption
      spy.reset();
      Page<DataUnitResource> backward =
          queries.listDataUnits(
              AddressScanOptions.of("ram:00004000", "ram:00004010", 1000), 2, "backward", null);
      assertEquals(1, spy.definedDataIterators.get());
      assertEquals(0, spy.statelessAfterBeforeCalls.get());
      assertEquals(
          List.of("ram:00004010", "ram:00004008"),
          backward.items().stream().map(DataUnitResource::address).toList());

      Page<DataUnitResource> backward2 =
          queries.listDataUnits(
              AddressScanOptions.of("ram:00004000", "ram:00004010", 1000),
              2,
              "backward",
              backward.nextCursor());
      assertEquals(
          List.of("ram:00004000"),
          backward2.items().stream().map(DataUnitResource::address).toList());
      assertTrue(backward2.scanProgress().complete());

      // Multi-byte start bound inside 4-byte dword (0x4002) skips 0x4000
      Page<DataUnitResource> midStart =
          queries.listDataUnits(
              AddressScanOptions.of("ram:00004002", "ram:00004010", 1000), 10, "forward", null);
      assertEquals(
          List.of("ram:00004008", "ram:00004010"),
          midStart.items().stream().map(DataUnitResource::address).toList());

      // Cursor resumption at maxAddress and minAddress
      spy.reset();
      Page<DataUnitResource> resumeMax =
          queries.listDataUnits(
              AddressScanOptions.of("ram:00004000", "ram:ffffffffffffffff", 1000),
              10,
              "forward",
              "ram:ffffffffffffffff");
      assertEquals(1, spy.definedDataIterators.get());
      assertTrue(resumeMax.items().isEmpty());
      assertTrue(resumeMax.scanProgress().complete());

      Page<DataUnitResource> resumeMin =
          queries.listDataUnits(
              AddressScanOptions.of("ram:0000000000000000", "ram:00004010", 1000),
              10,
              "backward",
              "ram:0000000000000000");
      assertTrue(resumeMin.items().isEmpty());
      assertTrue(resumeMin.scanProgress().complete());
    }
  }
}
