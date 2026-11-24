package app.byteland.ghidra.adapter.ghidra.function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraTestSupport;
import app.byteland.ghidra.adapter.ghidra.GhidraTestSupport.ProgramHolder;
import app.byteland.ghidra.adapter.ghidra.GhidraTestSupport.SeekSpy;
import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.ScanProgress;
import app.byteland.ghidra.service.function.FunctionResource;
import app.byteland.ghidra.service.function.FunctionService.FunctionQuery;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import java.io.ByteArrayInputStream;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class FunctionListQueriesTest {

  @Test
  void streamsFromFunctionManagerIteratorAndPreservesPaginationAndAllFilters() {
    AtomicReference<String> externalEntryRef = new AtomicReference<>();
    AtomicReference<String> externalCanonicalRef = new AtomicReference<>();
    try (ProgramHolder holder = GhidraTestSupport.createX64Program("functions_test")) {
      holder.inTransaction(
          program -> {
            AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
            Address base = space.getAddress(0x10000L);
            byte[] bytes = new byte[0x100];
            bytes[0x00] = (byte) 0x90;
            bytes[0x01] = (byte) 0xc3;
            bytes[0x10] = (byte) 0x90;
            bytes[0x11] = (byte) 0x90;
            bytes[0x12] = (byte) 0xc3;
            bytes[0x20] = (byte) 0xe9;
            bytes[0x30] = (byte) 0xc3;
            program
                .getMemory()
                .createInitializedBlock(
                    ".text",
                    base,
                    new ByteArrayInputStream(bytes),
                    bytes.length,
                    TaskMonitor.DUMMY,
                    false);

            FunctionManager fm = program.getFunctionManager();
            Function alpha =
                fm.createFunction(
                    "AlphaInit",
                    base,
                    new AddressSet(base, base.add(1)),
                    SourceType.USER_DEFINED);
            fm.createFunction(
                "BetaCompute",
                base.add(0x10),
                new AddressSet(base.add(0x10), base.add(0x12)),
                SourceType.USER_DEFINED);
            fm.createThunkFunction(
                "AlphaThunk",
                program.getGlobalNamespace(),
                base.add(0x20),
                new AddressSet(base.add(0x20), base.add(0x24)),
                alpha,
                SourceType.USER_DEFINED);
            fm.createFunction(
                "GammaExit",
                base.add(0x30),
                new AddressSet(base.add(0x30), base.add(0x30)),
                SourceType.USER_DEFINED);

            ExternalLocation extLoc =
                program
                    .getExternalManager()
                    .addExtFunction(
                        "libc.so.6", "puts", null, SourceType.IMPORTED);
            Address extEntry = extLoc.getFunction().getEntryPoint();
            externalEntryRef.set(extEntry.toString());
            externalCanonicalRef.set(AddressUtil.canonicalAddress(extEntry));

            Address maxAddr = space.getMaxAddress();
            program
                .getMemory()
                .createInitializedBlock(
                    ".high",
                    maxAddr,
                    new ByteArrayInputStream(new byte[] {(byte) 0xc3}),
                    1,
                    TaskMonitor.DUMMY,
                    false);
            fm.createFunction(
                "MaxEdgeFn",
                maxAddr,
                new AddressSet(maxAddr, maxAddr),
                SourceType.USER_DEFINED);
          });

      SeekSpy spy = new SeekSpy();
      FunctionServiceImpl service =
          new FunctionServiceImpl(GhidraTestSupport.sessionFor(spy.wrap(holder.program())));

      // 1. Stateful pagination: 1 FunctionManager.getFunctions iterator per page, 0 getFunctionAfter
      Page<FunctionResource> page1 =
          service.listFunctions(
              new FunctionQuery(
                  AddressScanOptions.of("ram:00010000", "ram:00010030", 1000),
                  2,
                  null,
                  null,
                  null,
                  null,
                  null,
                  null,
                  Set.of()));
      assertEquals(1, spy.functionIterators.get());
      assertEquals(0, spy.statelessAfterBeforeCalls.get());
      assertEquals(
          List.of("ram:00010000", "ram:00010010"),
          page1.items().stream().map(FunctionResource::entry).toList());
      assertEquals("ram:00010000", page1.scanProgress().scannedStart());
      assertEquals("ram:00010010", page1.scanProgress().scannedEnd());
      assertEquals(ScanProgress.StopReason.LIMIT, page1.scanProgress().stopReason());
      assertEquals("ram:00010010", page1.nextCursor());

      spy.reset();
      Page<FunctionResource> page2 =
          service.listFunctions(
              new FunctionQuery(
                  AddressScanOptions.of("ram:00010000", "ram:00010030", 1000),
                  2,
                  page1.nextCursor(),
                  null,
                  null,
                  null,
                  null,
                  null,
                  Set.of()));
      assertEquals(1, spy.functionIterators.get());
      assertEquals(0, spy.statelessAfterBeforeCalls.get());
      assertEquals(
          List.of("ram:00010020", "ram:00010030"),
          page2.items().stream().map(FunctionResource::entry).toList());
      assertEquals(ScanProgress.StopReason.LIMIT, page2.scanProgress().stopReason());

      spy.reset();
      Page<FunctionResource> page3 =
          service.listFunctions(
              new FunctionQuery(
                  AddressScanOptions.of("ram:00010000", "ram:00010030", 1000),
                  2,
                  page2.nextCursor(),
                  null,
                  null,
                  null,
                  null,
                  null,
                  Set.of()));
      assertEquals(1, spy.functionIterators.get());
      assertTrue(page3.items().isEmpty());
      assertTrue(page3.scanProgress().complete());
      assertNull(page3.nextCursor());

      // 2. Name filter (case-insensitive text match)
      Page<FunctionResource> byName =
          service.listFunctions(
              new FunctionQuery(
                  AddressScanOptions.of("ram:00010000", "ram:00010030", 1000),
                  10,
                  null,
                  "ALPHA",
                  null,
                  null,
                  null,
                  null,
                  Set.of()));
      assertEquals(
          List.of("AlphaInit", "AlphaThunk"),
          byName.items().stream().map(FunctionResource::name).toList());
      assertEquals("ram:00010000", byName.scanProgress().scannedStart());
      assertEquals("ram:00010030", byName.scanProgress().scannedEnd());
      assertTrue(byName.scanProgress().complete());

      // 3. Thunk filter (true and false)
      Page<FunctionResource> thunksOnly =
          service.listFunctions(
              new FunctionQuery(
                  AddressScanOptions.of("ram:00010000", "ram:00010030", 1000),
                  10,
                  null,
                  null,
                  null,
                  null,
                  null,
                  true,
                  Set.of()));
      assertEquals(
          List.of("AlphaThunk"),
          thunksOnly.items().stream().map(FunctionResource::name).toList());

      Page<FunctionResource> nonThunks =
          service.listFunctions(
              new FunctionQuery(
                  AddressScanOptions.of("ram:00010000", "ram:00010030", 1000),
                  10,
                  null,
                  null,
                  null,
                  null,
                  null,
                  false,
                  Set.of()));
      assertEquals(
          List.of("AlphaInit", "BetaCompute", "GammaExit"),
          nonThunks.items().stream().map(FunctionResource::name).toList());

      // 4. Contains filter (interior body address 0x10011 inside BetaCompute)
      Page<FunctionResource> containing =
          service.listFunctions(
              new FunctionQuery(
                  AddressScanOptions.of("ram:00010000", "ram:00010030", 1000),
                  10,
                  null,
                  null,
                  null,
                  "ram:00010011",
                  null,
                  null,
                  Set.of()));
      assertEquals(
          List.of("BetaCompute"),
          containing.items().stream().map(FunctionResource::name).toList());

      // 5. Entry filter on memory function and external function (direct getFunctionAt check)
      Page<FunctionResource> byEntry =
          service.listFunctions(
              new FunctionQuery(
                  AddressScanOptions.of(null, null, 1000),
                  10,
                  null,
                  null,
                  "ram:00010010",
                  null,
                  null,
                  null,
                  Set.of()));
      assertEquals(
          List.of("BetaCompute"),
          byEntry.items().stream().map(FunctionResource::name).toList());

      String externalEntry = externalEntryRef.get();
      spy.reset();
      Page<FunctionResource> externalPage =
          service.listFunctions(
              new FunctionQuery(
                  AddressScanOptions.of(null, null, 1000),
                  10,
                  null,
                  null,
                  externalEntry,
                  null,
                  true,
                  null,
                  Set.of()));
      assertEquals(1, spy.boundaryLookups.get());
      assertEquals(List.of("puts"), externalPage.items().stream().map(FunctionResource::name).toList());
      assertTrue(externalPage.items().getFirst().external());
      assertTrue(externalPage.scanProgress().complete());

      // External filter mismatch (external = false on external entry)
      Page<FunctionResource> externalFilteredOut =
          service.listFunctions(
              new FunctionQuery(
                  AddressScanOptions.of(null, null, 1000),
                  10,
                  null,
                  null,
                  externalEntry,
                  null,
                  false,
                  null,
                  Set.of()));
      assertTrue(externalFilteredOut.items().isEmpty());
      assertEquals(externalCanonicalRef.get(), externalFilteredOut.scanProgress().scannedStart());
      assertTrue(externalFilteredOut.scanProgress().complete());

      // A scan strictly after the external cursor does not emit the external function again
      Page<FunctionResource> afterExternal =
          service.listFunctions(
              new FunctionQuery(
                  AddressScanOptions.of(externalEntry, externalEntry, 1000),
                  10,
                  externalEntry,
                  null,
                  null,
                  null,
                  null,
                  null,
                  Set.of()));
      assertTrue(afterExternal.items().isEmpty());
      assertFalse(afterExternal.scanProgress().scannedStart() != null);
      assertTrue(afterExternal.scanProgress().complete());

      // 6. Cursor resumption at maxAddress (ram:ffffffffffffffff) skips MaxEdgeFn without overflow
      spy.reset();
      Page<FunctionResource> resumeAtMax =
          service.listFunctions(
              new FunctionQuery(
                  AddressScanOptions.of("ram:00010000", "ram:ffffffffffffffff", 1000),
                  10,
                  "ram:ffffffffffffffff",
                  null,
                  null,
                  null,
                  null,
                  null,
                  Set.of()));
      assertEquals(1, spy.functionIterators.get());
      assertTrue(resumeAtMax.items().isEmpty());
      assertTrue(resumeAtMax.scanProgress().complete());
      assertNull(resumeAtMax.nextCursor());
    }
  }
}
