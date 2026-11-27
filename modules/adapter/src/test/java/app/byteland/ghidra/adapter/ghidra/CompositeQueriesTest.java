package app.byteland.ghidra.adapter.ghidra;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.adapter.ghidra.GhidraTestSupport.ProgramHolder;
import app.byteland.ghidra.adapter.ghidra.listing.ListingServiceImpl;
import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.ScanProgress;
import app.byteland.ghidra.service.comment.CommentResource;
import app.byteland.ghidra.service.listing.CodeUnitResource;
import app.byteland.ghidra.service.listing.ListingWindowResource;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import java.io.ByteArrayInputStream;
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
}
