package app.byteland.ghidra.adapter.ghidra;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.adapter.ghidra.GhidraTestSupport.ProgramHolder;
import app.byteland.ghidra.adapter.ghidra.function.FunctionServiceImpl;
import app.byteland.ghidra.adapter.ghidra.listing.ListingServiceImpl;
import app.byteland.ghidra.adapter.ghidra.reference.ReferenceServiceImpl;
import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.ScanProgress;
import app.byteland.ghidra.service.comment.CommentResource;
import app.byteland.ghidra.service.function.ControlFlowGraphResource;
import app.byteland.ghidra.service.listing.CodeUnitResource;
import app.byteland.ghidra.service.listing.ListingWindowResource;
import app.byteland.ghidra.service.reference.ReferenceContextResource;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;
import java.io.ByteArrayInputStream;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class CompositeQueriesTest {

  @Test
  void listingWindowGetCoversInitializedCodeDataCommentsRefsAndUninitializedBss() {
    try (ProgramHolder holder = GhidraTestSupport.createX64Program("listing_window_test")) {
      holder.inTransaction(
          program -> {
            AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
            Address textBase = space.getAddress(0x1000L);
            // Chunk 1 at 0x1000 calls 0x1010 and returns at 0x1005.
            // A 32-bit data value is at 0x1008, and 0x1010 returns.
            byte[] textBytes = new byte[0x20];
            textBytes[0x00] = (byte) 0xe8;
            textBytes[0x01] = 0x0b;
            textBytes[0x05] = (byte) 0xc3;
            textBytes[0x08] = 0x2a;
            textBytes[0x10] = (byte) 0xc3;
            program
                .getMemory()
                .createInitializedBlock(
                    ".text",
                    textBase,
                    new ByteArrayInputStream(textBytes),
                    textBytes.length,
                    TaskMonitor.DUMMY,
                    false);

            AddressSet entrySet = new AddressSet(textBase, textBase.add(5));
            new DisassembleCommand(textBase, entrySet, false)
                .applyTo(program, TaskMonitor.DUMMY);
            Address calleeAddr = textBase.add(0x10);
            new DisassembleCommand(calleeAddr, new AddressSet(calleeAddr, calleeAddr), false)
                .applyTo(program, TaskMonitor.DUMMY);
            program.getListing().createData(textBase.add(8), DWordDataType.dataType);

            FunctionManager fm = program.getFunctionManager();
            fm.createFunction("_ZN4demo6callerEv", textBase, entrySet, SourceType.USER_DEFINED);
            fm.createFunction(
                "callee_fn",
                calleeAddr,
                new AddressSet(calleeAddr, calleeAddr),
                SourceType.USER_DEFINED);

            program
                .getListing()
                .setComment(textBase, CommentType.EOL, "call into callee_fn");

            Address bssBase = space.getAddress(0x2000L);
            program
                .getMemory()
                .createUninitializedBlock(".bss", bssBase, 0x10, false);
            program.getListing().createData(bssBase, DWordDataType.dataType);
            program
                .getSymbolTable()
                .createLabel(bssBase, "g_counter", SourceType.USER_DEFINED);
          });

      ListingServiceImpl listing =
          new ListingServiceImpl(GhidraTestSupport.sessionFor(holder.program()));

      ListingWindowResource textWindow =
          listing.getListingWindow(
              AddressScanOptions.of("ram:00001000", "ram:00001015", 10_000),
              50,
              "all",
              null);
      assertTrue(textWindow.scan().complete());
      assertNull(textWindow.nextCursor());
      assertFalse(textWindow.items().isEmpty());
      assertEquals(1, textWindow.dataUnits().size());
      assertEquals("ram:00001008", textWindow.dataUnits().getFirst().address());
      assertNotNull(textWindow.dataUnits().getFirst().representation());
      assertEquals(2, textWindow.functions().size());
      assertEquals("_ZN4demo6callerEv", textWindow.functions().getFirst().name());
      assertEquals(
          CppSymbolNames.demangled(
              holder.program(),
              "_ZN4demo6callerEv",
              holder.program().getAddressFactory().getDefaultAddressSpace().getAddress(0x1000L)),
          textWindow.functions().getFirst().demangledName());
      assertEquals(1, textWindow.comments().size());
      assertEquals(CommentResource.Type.EOL, textWindow.comments().getFirst().type());
      assertTrue(
          textWindow.outgoingReferences().stream()
              .anyMatch(
                  ref ->
                      "ram:00001000".equals(ref.from()) && "ram:00001010".equals(ref.to())));
      assertTrue(
          textWindow.incomingReferences().stream()
              .anyMatch(
                  ref ->
                      "ram:00001000".equals(ref.from()) && "ram:00001010".equals(ref.to())));

      // Pagination across the text window
      ListingWindowResource page1 =
          listing.getListingWindow(
              AddressScanOptions.of("ram:00001000", "ram:00001015", 10_000),
              2,
              "all",
              null);
      assertEquals(2, page1.items().size());
      assertEquals("ram:00001005", page1.nextCursor());
      assertEquals(ScanProgress.StopReason.LIMIT, page1.scan().stopReason());

      ListingWindowResource page2 =
          listing.getListingWindow(
              AddressScanOptions.of("ram:00001000", "ram:00001015", 10_000),
              50,
              "all",
              page1.nextCursor());
      assertEquals("ram:00001006", page2.items().getFirst().address());
      assertNull(page2.nextCursor());

      // Uninitialized .bss block omits raw bytes cleanly
      ListingWindowResource bssWindow =
          listing.getListingWindow(
              AddressScanOptions.of("ram:00002000", "ram:0000200f", 10_000),
              50,
              "all",
              null);
      assertFalse(bssWindow.items().isEmpty());
      CodeUnitResource bssData = bssWindow.items().getFirst();
      assertEquals("ram:00002000", bssData.address());
      assertEquals(CodeUnitResource.Kind.DATA, bssData.kind());
      assertEquals(4, bssData.length());
      assertNull(bssData.bytes());
      assertEquals(1, bssWindow.dataUnits().size());
      assertNull(bssWindow.dataUnits().getFirst().bytes());
      assertTrue(
          bssWindow.symbols().stream().anyMatch(symbol -> "g_counter".equals(symbol.name())));
    }
  }

  @Test
  void controlFlowGraphGetHandlesDiscontiguousBodiesExternalTargetsAndLimits() {
    AtomicReference<String> externalEntryRef = new AtomicReference<>();
    try (ProgramHolder holder = GhidraTestSupport.createX64Program("cfg_discontiguous_test")) {
      holder.inTransaction(
          program -> {
            AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
            Address base = space.getAddress(0x3000L);
            // Chunk 1 is at 0x3000..0x3004 and branches to 0x3020.
            // A separate function is at 0x3010..0x3011 between the two chunks.
            // Chunk 2 at 0x3020..0x3023 jumps to 0x3040 and has an indirect jump.
            byte[] bytes = new byte[0x50];
            bytes[0x00] = (byte) 0x85;
            bytes[0x01] = (byte) 0xff;
            bytes[0x02] = 0x74;
            bytes[0x03] = 0x1c;
            bytes[0x04] = (byte) 0xc3;

            bytes[0x10] = (byte) 0x90;
            bytes[0x11] = (byte) 0xc3;

            bytes[0x20] = (byte) 0xeb;
            bytes[0x21] = 0x1e;
            bytes[0x22] = (byte) 0xff;
            bytes[0x23] = (byte) 0xe0;

            bytes[0x40] = (byte) 0xc3;

            program
                .getMemory()
                .createInitializedBlock(
                    ".text",
                    base,
                    new ByteArrayInputStream(bytes),
                    bytes.length,
                    TaskMonitor.DUMMY,
                    false);

            AddressSet disasmSet = new AddressSet();
            disasmSet.add(base, base.add(4));
            disasmSet.add(base.add(0x10), base.add(0x11));
            disasmSet.add(base.add(0x20), base.add(0x23));
            disasmSet.add(base.add(0x40), base.add(0x40));
            new DisassembleCommand(disasmSet, disasmSet, false)
                .applyTo(program, TaskMonitor.DUMMY);

            FunctionManager fm = program.getFunctionManager();
            AddressSet splitBody = new AddressSet(base, base.add(4));
            splitBody.add(base.add(0x20), base.add(0x23));
            fm.createFunction("_ZN4demo8split_fnEi", base, splitBody, SourceType.USER_DEFINED);
            fm.createFunction(
                "interstitial_fn",
                base.add(0x10),
                new AddressSet(base.add(0x10), base.add(0x11)),
                SourceType.USER_DEFINED);

            ExternalLocation ext =
                program
                    .getExternalManager()
                    .addExtFunction("libc.so.6", "puts", null, SourceType.IMPORTED);
            externalEntryRef.set(AddressUtil.canonicalAddress(ext.getFunction().getEntryPoint()));
          });

      FunctionServiceImpl functions =
          new FunctionServiceImpl(GhidraTestSupport.sessionFor(holder.program()));

      ControlFlowGraphResource byEntry =
          functions.getControlFlowGraph("ram:00003000", null, 4096, 10_000);
      ControlFlowGraphResource byTailAddress =
          functions.getControlFlowGraph(null, "ram:00003022", 4096, 10_000);

      assertEquals(byEntry.entry(), byTailAddress.entry());
      assertEquals(byEntry.blocks(), byTailAddress.blocks());
      assertEquals(byEntry.nodes(), byTailAddress.nodes());
      assertEquals(byEntry.edges(), byTailAddress.edges());
      assertTrue(byEntry.hasBody());
      assertEquals("_ZN4demo8split_fnEi", byEntry.name());
      assertEquals(
          CppSymbolNames.demangled(
              holder.program(),
              "_ZN4demo8split_fnEi",
              holder.program().getAddressFactory().getDefaultAddressSpace().getAddress(0x3000L)),
          byEntry.demangledName());
      assertEquals(1, byEntry.unresolvedJumps());

      // Interstitial instructions at 0x3010..0x3011 never appear in split_fn blocks
      List<String> blockInstructionAddresses =
          byEntry.blocks().stream()
              .flatMap(block -> block.instructions().stream())
              .map(ControlFlowGraphResource.BlockInstructionResource::address)
              .toList();
      assertEquals(
          List.of(
              "ram:00003000",
              "ram:00003002",
              "ram:00003004",
              "ram:00003020",
              "ram:00003022"),
          blockInstructionAddresses);

      // Conditional branch produces taken and fallthrough edges, plus external target node
      assertTrue(byEntry.edges().stream().anyMatch(edge -> "taken".equals(edge.kind())));
      assertTrue(byEntry.edges().stream().anyMatch(edge -> "fallthrough".equals(edge.kind())));
      assertTrue(
          byEntry.nodes().stream()
              .anyMatch(
                  node ->
                      "external".equals(node.kind()) && "ram:00003040".equals(node.address())));

      // Bounded maxInstructions stops at LIMIT
      ControlFlowGraphResource limited =
          functions.getControlFlowGraph("ram:00003000", null, 2, 10_000);
      assertFalse(limited.scan().complete());
      assertEquals(ScanProgress.StopReason.LIMIT, limited.scan().stopReason());

      // External function returns hasBody = false
      ControlFlowGraphResource externalCfg =
          functions.getControlFlowGraph(externalEntryRef.get(), null, 4096, 10_000);
      assertFalse(externalCfg.hasBody());
      assertNull(externalCfg.body());
      assertTrue(externalCfg.blocks().isEmpty());
    }
  }

  @Test
  void referenceContextListEnrichesCallersSupportsSymbolIdAndPaginates() {
    AtomicReference<String> targetSymbolIdRef = new AtomicReference<>();
    try (ProgramHolder holder = GhidraTestSupport.createX64Program("reference_context_test")) {
      holder.inTransaction(
          program -> {
            AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
            Address base = space.getAddress(0x4000L);
            // Two caller functions at 0x4000 and 0x4010 call 0x4030.
            // An orphan instruction is at 0x4020, and data is at 0x4040.
            byte[] bytes = new byte[0x50];
            bytes[0x00] = (byte) 0xe8;
            bytes[0x01] = 0x2b;
            bytes[0x05] = (byte) 0xc3;

            bytes[0x10] = (byte) 0xe8;
            bytes[0x11] = 0x1b;
            bytes[0x15] = (byte) 0xc3;

            bytes[0x20] = (byte) 0x90;
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

            AddressSet codeSet = new AddressSet();
            codeSet.add(base, base.add(5));
            codeSet.add(base.add(0x10), base.add(0x15));
            codeSet.add(base.add(0x20), base.add(0x20));
            codeSet.add(base.add(0x30), base.add(0x30));
            new DisassembleCommand(codeSet, codeSet, false).applyTo(program, TaskMonitor.DUMMY);
            program.getListing().createData(base.add(0x40), DWordDataType.dataType);

            FunctionManager fm = program.getFunctionManager();
            fm.createFunction(
                "_ZN4demo7callerAEv",
                base,
                new AddressSet(base, base.add(5)),
                SourceType.USER_DEFINED);
            fm.createFunction(
                "callerB",
                base.add(0x10),
                new AddressSet(base.add(0x10), base.add(0x15)),
                SourceType.USER_DEFINED);
            Address targetEntry = base.add(0x30);
            fm.createFunction(
                "target_fn",
                targetEntry,
                new AddressSet(targetEntry, targetEntry),
                SourceType.USER_DEFINED);

            ReferenceManager rm = program.getReferenceManager();
            rm.addMemoryReference(
                base.add(0x20), targetEntry, RefType.READ, SourceType.USER_DEFINED, 0);
            rm.addMemoryReference(
                base.add(0x40), targetEntry, RefType.DATA, SourceType.USER_DEFINED, 0);

            Symbol primary = program.getSymbolTable().getPrimarySymbol(targetEntry);
            targetSymbolIdRef.set(Long.toString(primary.getID()));
          });

      ReferenceServiceImpl references =
          new ReferenceServiceImpl(GhidraTestSupport.sessionFor(holder.program()));

      Page<ReferenceContextResource> allBySymbol =
          references.listReferenceContext(
              null,
              null,
              targetSymbolIdRef.get(),
              null,
              AddressScanOptions.of(null, null, 10_000),
              10,
              null);
      assertEquals(4, allBySymbol.items().size());
      assertTrue(allBySymbol.scanProgress().complete());

      ReferenceContextResource first = allBySymbol.items().get(0);
      assertEquals("ram:00004000", first.from());
      assertEquals("ram:00004000", first.callSite());
      assertNotNull(first.caller());
      assertEquals("ram:00004000", first.caller().entry());
      assertEquals("_ZN4demo7callerAEv", first.caller().name());
      assertEquals("Global", first.caller().namespace());
      assertEquals(
          CppSymbolNames.demangled(
              holder.program(),
              "_ZN4demo7callerAEv",
              holder.program().getAddressFactory().getDefaultAddressSpace().getAddress(0x4000L)),
          first.caller().demangledName());

      ReferenceContextResource second = allBySymbol.items().get(1);
      assertEquals("ram:00004010", second.from());
      assertEquals("callerB", second.caller().name());
      assertNull(second.caller().demangledName());

      ReferenceContextResource orphanInsn = allBySymbol.items().get(2);
      assertEquals("ram:00004020", orphanInsn.from());
      assertEquals("ram:00004020", orphanInsn.callSite());
      assertNull(orphanInsn.caller());

      ReferenceContextResource dataRef = allBySymbol.items().get(3);
      assertEquals("ram:00004040", dataRef.from());
      assertNull(dataRef.callSite());
      assertNull(dataRef.caller());

      // Filter by UNCONDITIONAL_CALL and paginate 1 item per page
      Page<ReferenceContextResource> callsPage1 =
          references.listReferenceContext(
              null,
              "ram:00004030",
              null,
              "UNCONDITIONAL_CALL",
              AddressScanOptions.of(null, null, 10_000),
              1,
              null);
      assertEquals(1, callsPage1.items().size());
      assertEquals("ram:00004000", callsPage1.items().getFirst().from());
      assertNotNull(callsPage1.nextCursor());

      Page<ReferenceContextResource> callsPage2 =
          references.listReferenceContext(
              null,
              "ram:00004030",
              null,
              "UNCONDITIONAL_CALL",
              AddressScanOptions.of(null, null, 10_000),
              10,
              callsPage1.nextCursor());
      assertEquals(1, callsPage2.items().size());
      assertEquals("ram:00004010", callsPage2.items().getFirst().from());
      assertNull(callsPage2.nextCursor());
    }
  }
}
