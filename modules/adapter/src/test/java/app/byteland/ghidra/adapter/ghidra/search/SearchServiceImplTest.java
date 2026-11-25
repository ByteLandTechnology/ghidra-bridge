package app.byteland.ghidra.adapter.ghidra.search;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.GhidraTestSupport;
import app.byteland.ghidra.adapter.ghidra.GhidraTestSupport.ProgramHolder;
import app.byteland.ghidra.adapter.ghidra.globalvariable.GlobalVariableServiceImpl;
import app.byteland.ghidra.adapter.ghidra.memory.MemoryServiceImpl;
import app.byteland.ghidra.adapter.ghidra.symbol.SymbolServiceImpl;
import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.ScanProgress;
import app.byteland.ghidra.service.analysis.AnalysisResource;
import app.byteland.ghidra.service.analysis.AnalysisService;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService;
import app.byteland.ghidra.service.memory.MemoryService;
import app.byteland.ghidra.service.search.BytePatternMatchesResource;
import app.byteland.ghidra.service.search.ByteSearchResult;
import app.byteland.ghidra.service.search.SearchService.ByteSearchQuery;
import app.byteland.ghidra.service.search.SearchService.EncodingFilter;
import app.byteland.ghidra.service.search.SearchService.StringSearchQuery;
import app.byteland.ghidra.service.search.StringMatchResource;
import app.byteland.ghidra.service.search.StringSearchResult;
import app.byteland.ghidra.service.symbol.SymbolResource;
import app.byteland.ghidra.service.symbol.SymbolService;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.data.TerminatedUnicodeDataType;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import java.io.ByteArrayInputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class SearchServiceImplTest {

  @Test
  void cachesDefinedAndUndefinedAsciiAndUtf16StringsWithoutRescanningIterators() throws Exception {
    try (ProgramHolder holder = GhidraTestSupport.createX64Program("string-cache-test")) {
      holder.inTransaction(
          program -> {
            Memory memory = program.getMemory();
            byte[] blockBytes = new byte[512];
            writeNullTerminated(
                blockBytes, 0x00, "https://api.byteland.app/v1".getBytes(StandardCharsets.US_ASCII), 1);
            writeNullTerminated(
                blockBytes, 0x40, "WideDefinedKey".getBytes(StandardCharsets.UTF_16LE), 2);
            writeNullTerminated(
                blockBytes, 0x80, "UndefinedSecretToken".getBytes(StandardCharsets.US_ASCII), 1);
            // Put an odd-offset zero byte at 0xBF before aligned UTF-16LE at 0xC0.
            blockBytes[0xBF] = 0;
            writeNullTerminated(
                blockBytes, 0xC0, "Software\\Vendor\\Agent".getBytes(StandardCharsets.UTF_16LE), 2);
            writeNullTerminated(
                blockBytes, 0x120, "BigEndianMarker".getBytes(StandardCharsets.UTF_16BE), 2);

            Address base = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x401000L);
            memory.createInitializedBlock(
                ".rdata",
                base,
                new ByteArrayInputStream(blockBytes),
                blockBytes.length,
                TaskMonitor.DUMMY,
                false);
            memory.createUninitializedBlock(
                ".bss", base.add(0x2000L), 0x100L, false);

            DataUtilities.createData(
                program,
                base,
                TerminatedStringDataType.dataType,
                -1,
                DataUtilities.ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
            DataUtilities.createData(
                program,
                base.add(0x40L),
                TerminatedUnicodeDataType.dataType,
                -1,
                DataUtilities.ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
          });

      ScanSpy spy = new ScanSpy();
      Program wrapped = spy.wrap(holder.program());
      GhidraSession session = GhidraTestSupport.sessionFor(wrapped);
      StubAnalysisService analysis = new StubAnalysisService();
      MemoryService memoryService = new MemoryServiceImpl(session);
      SearchServiceImpl searchService = new SearchServiceImpl(session, analysis, memoryService);

      StringSearchResult initial =
          searchService.searchStrings(
              new StringSearchQuery(
                  AddressScanOptions.of(null, null, 5000),
                  100,
                  null,
                  null,
                  null,
                  EncodingFilter.ALL,
                  null,
                  null,
                  false));

      assertTrue(initial.indexComplete());
      assertEquals(5, initial.totalIndexed());
      assertEquals(5, initial.page().items().size());
      assertTrue(spy.listingCalls.get() > 0);
      assertTrue(spy.memoryReadCalls.get() > 0);

      StringMatchResource first = initial.page().items().get(0);
      assertEquals("ram:00401000", first.address());
      assertEquals("https://api.byteland.app/v1", first.value());
      assertEquals(StringMatchResource.Encoding.ASCII, first.encoding());
      assertTrue(first.defined());
      assertNotNull(first.dataType());

      StringMatchResource second = initial.page().items().get(1);
      assertEquals("ram:00401040", second.address());
      assertEquals("WideDefinedKey", second.value());
      assertEquals(StringMatchResource.Encoding.UTF16LE, second.encoding());
      assertTrue(second.defined());

      StringMatchResource third = initial.page().items().get(2);
      assertEquals("ram:00401080", third.address());
      assertEquals("UndefinedSecretToken", third.value());
      assertEquals(StringMatchResource.Encoding.ASCII, third.encoding());
      assertFalse(third.defined());
      assertNull(third.dataType());

      StringMatchResource fourth = initial.page().items().get(3);
      assertEquals("ram:004010c0", fourth.address());
      assertEquals("Software\\Vendor\\Agent", fourth.value());
      assertEquals(StringMatchResource.Encoding.UTF16LE, fourth.encoding());
      assertFalse(fourth.defined());

      StringMatchResource fifth = initial.page().items().get(4);
      assertEquals("ram:00401120", fifth.address());
      assertEquals("BigEndianMarker", fifth.value());
      assertEquals(StringMatchResource.Encoding.UTF16BE, fifth.encoding());
      assertFalse(fifth.defined());

      spy.reset();

      // Run consecutive text, regex, encoding, defined, and range queries from cache.
      StringSearchResult regexHit =
          searchService.searchStrings(
              new StringSearchQuery(
                  AddressScanOptions.of(null, null, 5000),
                  100,
                  null,
                  null,
                  "software\\\\vendor\\\\[a-z]+",
                  EncodingFilter.UTF16,
                  false,
                  null,
                  false));
      assertEquals(1, regexHit.page().items().size());
      assertEquals("Software\\Vendor\\Agent", regexHit.page().items().getFirst().value());

      StringSearchResult caseSensitiveMiss =
          searchService.searchStrings(
              new StringSearchQuery(
                  AddressScanOptions.of(null, null, 5000),
                  100,
                  null,
                  null,
                  "software\\\\vendor",
                  EncodingFilter.ALL,
                  null,
                  null,
                  true));
      assertEquals(0, caseSensitiveMiss.page().items().size());

      StringSearchResult beHit =
          searchService.searchStrings(
              new StringSearchQuery(
                  AddressScanOptions.of(null, null, 5000),
                  100,
                  null,
                  "bigendian",
                  null,
                  EncodingFilter.UTF16BE,
                  null,
                  null,
                  false));
      assertEquals(1, beHit.page().items().size());
      assertEquals("BigEndianMarker", beHit.page().items().getFirst().value());

      StringSearchResult ranged =
          searchService.searchStrings(
              new StringSearchQuery(
                  AddressScanOptions.of("0x401040", "0x401080", 5000),
                  100,
                  null,
                  null,
                  null,
                  EncodingFilter.ALL,
                  null,
                  null,
                  false));
      assertEquals(2, ranged.page().items().size());

      assertEquals(0, spy.listingCalls.get());
      assertEquals(0, spy.memoryReadCalls.get());
    }
  }

  @Test
  void invalidatesAffectedEntriesOnMemoryGlobalVariableAndSymbolMutationsAndGuardsActiveAnalysis()
      throws Exception {
    try (ProgramHolder holder = GhidraTestSupport.createX64Program("invalidation-test")) {
      holder.inTransaction(
          program -> {
            byte[] data = new byte[256];
            writeNullTerminated(
                data, 0x00, "InitialAlphaValue".getBytes(StandardCharsets.US_ASCII), 1);
            writeNullTerminated(
                data, 0x40, "UntouchedBetaValue".getBytes(StandardCharsets.US_ASCII), 1);
            Address base = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x500000L);
            program
                .getMemory()
                .createInitializedBlock(
                    ".data",
                    base,
                    new ByteArrayInputStream(data),
                    data.length,
                    TaskMonitor.DUMMY,
                    false);
            program
                .getDataTypeManager()
                .addDataType(TerminatedStringDataType.dataType, null);
            program
                .getSymbolTable()
                .createLabel(base.add(0x40L), "beta_label", SourceType.USER_DEFINED);
          });

      GhidraSession session = GhidraTestSupport.sessionFor(holder.program());
      StubAnalysisService analysis = new StubAnalysisService();
      MemoryService memoryService = new MemoryServiceImpl(session);
      GlobalVariableService globalVariableService = new GlobalVariableServiceImpl(session);
      SymbolService symbolService = new SymbolServiceImpl(session);
      SearchServiceImpl searchService = new SearchServiceImpl(session, analysis, memoryService);

      // Queries issued while background analysis runs report indexComplete = false.
      analysis.running.set(true);
      StringSearchResult duringAnalysis =
          searchService.searchStrings(allStringsQuery(null, null));
      assertFalse(duringAnalysis.indexComplete());
      assertEquals(2, duringAnalysis.page().items().size());

      // Finish analysis and notify session; subsequent query builds permanent cache.
      analysis.running.set(false);
      session.notifyProgramMutated(null);

      StringSearchResult settled = searchService.searchStrings(allStringsQuery(null, null));
      assertTrue(settled.indexComplete());
      long modBeforeWrite = settled.modificationNumber();

      // Mutate memory through memory.write inside a committed transaction.
      byte[] patched = "MutatedGammaVal!\0".getBytes(StandardCharsets.US_ASCII);
      session.withTransaction(
          () -> {
            memoryService.patchMemory(
                "0x500000",
                new ByteSequence(
                    ByteSequence.Encoding.HEX,
                    HexFormat.of().formatHex(patched),
                    patched.length));
            return null;
          });

      StringSearchResult afterMemoryWrite =
          searchService.searchStrings(allStringsQuery("MutatedGammaVal!", null));
      assertTrue(afterMemoryWrite.indexComplete());
      assertEquals(1, afterMemoryWrite.page().items().size());
      assertFalse(afterMemoryWrite.page().items().getFirst().defined());
      assertTrue(afterMemoryWrite.modificationNumber() > modBeforeWrite);

      // Define a global string variable at 0x500000 and verify defined status updates.
      String stringTypeName = TerminatedStringDataType.dataType.getName();
      session.withTransaction(
          () -> {
            globalVariableService.writeGlobalVariable(
                new GlobalVariableService.Mutation(
                    "0x500000", "g_gamma", DataTypeReference.named(stringTypeName)),
                GlobalVariableService.WriteMode.CREATE);
            return null;
          });

      StringSearchResult afterGlobalCreate =
          searchService.searchStrings(allStringsQuery("MutatedGammaVal!", null));
      assertEquals(1, afterGlobalCreate.page().items().size());
      assertTrue(afterGlobalCreate.page().items().getFirst().defined());
      assertNotNull(afterGlobalCreate.page().items().getFirst().dataType());

      // Delete the global variable and verify defined status reverts to false.
      session.withTransaction(
          () -> {
            globalVariableService.deleteGlobalVariable("0x500000", true);
            return null;
          });
      StringSearchResult afterGlobalDelete =
          searchService.searchStrings(allStringsQuery("MutatedGammaVal!", null));
      assertEquals(1, afterGlobalDelete.page().items().size());
      assertFalse(afterGlobalDelete.page().items().getFirst().defined());

      // Rename symbol at 0x500040 and verify cache reflects updated modification number.
      long modBeforeSymbol = afterGlobalDelete.modificationNumber();
      SymbolResource betaSym =
          symbolService
              .listSymbols(
                  new SymbolService.SymbolQuery(
                      AddressScanOptions.of(null, null, 5000),
                      "beta_label",
                      null,
                      null,
                      null,
                      null,
                      true,
                      10,
                      null))
              .items()
              .getFirst();
      session.withTransaction(
          () -> {
            symbolService.renameSymbol(Long.parseLong(betaSym.id()), "beta_renamed");
            return null;
          });
      StringSearchResult afterSymbolRename =
          searchService.searchStrings(allStringsQuery("UntouchedBetaValue", null));
      assertEquals(1, afterSymbolRename.page().items().size());
      assertTrue(afterSymbolRename.modificationNumber() > modBeforeSymbol);
    }
  }

  @Test
  void enforcesEntryCountAndStringByteLengthCaps() throws Exception {
    try (ProgramHolder holder = GhidraTestSupport.createX64Program("caps-test")) {
      holder.inTransaction(
          program -> {
            byte[] block = new byte[256];
            writeNullTerminated(
                block, 0x00, "ABCDEFGHIJKLMNOPQRST".getBytes(StandardCharsets.US_ASCII), 1);
            writeNullTerminated(block, 0x30, "SecondEntry".getBytes(StandardCharsets.US_ASCII), 1);
            writeNullTerminated(block, 0x60, "ThirdEntry!".getBytes(StandardCharsets.US_ASCII), 1);
            Address base = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x600000L);
            program
                .getMemory()
                .createInitializedBlock(
                    ".rodata",
                    base,
                    new ByteArrayInputStream(block),
                    block.length,
                    TaskMonitor.DUMMY,
                    false);
          });

      GhidraSession session = GhidraTestSupport.sessionFor(holder.program());
      StubAnalysisService analysis = new StubAnalysisService();
      StringIndexCache cappedCache = new StringIndexCache(session, analysis, 2, 8);
      SearchServiceImpl searchService =
          new SearchServiceImpl(cappedCache, new MemoryServiceImpl(session));

      StringSearchResult result = searchService.searchStrings(allStringsQuery(null, null));
      assertTrue(result.indexComplete());
      assertEquals(2, result.totalIndexed());
      assertEquals(2, result.page().items().size());
      assertEquals("ABCDEFGH", result.page().items().getFirst().value());
      assertEquals(8, result.page().items().getFirst().length());
    }
  }

  @Test
  void scansBatchWildcardBytePatternsAcrossInitializedBlocksAndChunkBoundaries() throws Exception {
    try (ProgramHolder holder = GhidraTestSupport.createX64Program("byte-scan-test")) {
      holder.inTransaction(
          program -> {
            byte[] textBytes = new byte[70_000];
            // Place prologue at 0x00, chunk-boundary signature at 65_534, and another at 66_000.
            byte[] prologue1 = HexFormat.of().parseHex("48895c2408");
            byte[] prologue2 = HexFormat.of().parseHex("48895c2418");
            byte[] cipherSig = HexFormat.of().parseHex("ff15a3b4c5d6");
            System.arraycopy(prologue1, 0, textBytes, 0x10, prologue1.length);
            System.arraycopy(prologue2, 0, textBytes, 65_534, prologue2.length);
            System.arraycopy(cipherSig, 0, textBytes, 66_000, cipherSig.length);

            Address base = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x700000L);
            program
                .getMemory()
                .createInitializedBlock(
                    ".text",
                    base,
                    new ByteArrayInputStream(textBytes),
                    textBytes.length,
                    TaskMonitor.DUMMY,
                    false);
            program
                .getMemory()
                .createUninitializedBlock(".bss", base.add(0x20000L), 0x1000L, false);
          });

      GhidraSession session = GhidraTestSupport.sessionFor(holder.program());
      MemoryServiceImpl memoryService = new MemoryServiceImpl(session);
      SearchServiceImpl searchService =
          new SearchServiceImpl(session, new StubAnalysisService(), memoryService);

      List<String> patterns = List.of("48 89 5c 24 ??", "ff 15 ?? b4 ?? d6", "deadbeef");

      // Paginate with limit = 2 across the 3 total matches.
      ByteSearchResult page1 =
          searchService.searchBytes(
              new ByteSearchQuery(AddressScanOptions.of(null, null, 5000), 2, null, patterns));
      assertEquals(2, page1.totalMatches());
      assertEquals(ScanProgress.StopReason.LIMIT, page1.scan().stopReason());
      assertFalse(page1.scan().complete());
      assertNotNull(page1.nextCursor());
      assertEquals(
          List.of("ram:00700010", "ram:0070fffe"),
          page1.items().get(0).matches());
      assertEquals(List.of(), page1.items().get(1).matches());
      assertEquals(List.of(), page1.items().get(2).matches());

      ByteSearchResult page2 =
          searchService.searchBytes(
              new ByteSearchQuery(
                  AddressScanOptions.of(null, null, 5000), 2, page1.nextCursor(), patterns));
      assertEquals(1, page2.totalMatches());
      assertEquals(ScanProgress.StopReason.COMPLETED, page2.scan().stopReason());
      assertTrue(page2.scan().complete());
      assertNull(page2.nextCursor());
      assertEquals(List.of(), page2.items().get(0).matches());
      assertEquals(List.of("ram:007101d0"), page2.items().get(1).matches());
      assertEquals(List.of(), page2.items().get(2).matches());

      assertThrows(
          IllegalArgumentException.class,
          () ->
              searchService.searchBytes(
                  new ByteSearchQuery(
                      AddressScanOptions.of(null, null, 1000), 10, null, List.of("48 8"))));
    }
  }

  @Test
  void scansStringsInsideUndefinedSymbolArraysAndExcludesNonLoadedOverlaysByDefault()
      throws Exception {
    try (ProgramHolder holder = GhidraTestSupport.createX64Program("elf-symbol-array-test")) {
      holder.inTransaction(
          program -> {
            Memory memory = program.getMemory();
            byte[] rodata = new byte[128];
            byte[] wideLe = "WideElfSymbolPayload".getBytes(StandardCharsets.UTF_16LE);
            writeNullTerminated(rodata, 0x10, wideLe, 2);
            Address base =
                program.getAddressFactory().getDefaultAddressSpace().getAddress(0x402000L);
            memory.createInitializedBlock(
                ".rodata",
                base,
                new ByteArrayInputStream(rodata),
                rodata.length,
                TaskMonitor.DUMMY,
                false);
            // Create an undefined1[N] array like Ghidra ElfLoader creates for an STT_OBJECT symbol.
            ArrayDataType undefinedArray =
                new ArrayDataType(Undefined1DataType.dataType, wideLe.length + 2, 1);
            DataUtilities.createData(
                program,
                base.add(0x10L),
                undefinedArray,
                -1,
                DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);

            // Non-loaded OTHER overlay section (such as .strtab or .comment).
            byte[] commentBytes = new byte[64];
            writeNullTerminated(
                commentBytes, 0x00, "GCC: non-loaded comment".getBytes(StandardCharsets.US_ASCII), 1);
            memory.createInitializedBlock(
                ".comment",
                AddressSpace.OTHER_SPACE.getAddress(0L),
                new ByteArrayInputStream(commentBytes),
                commentBytes.length,
                TaskMonitor.DUMMY,
                true);
          });

      GhidraSession session = GhidraTestSupport.sessionFor(holder.program());
      SearchServiceImpl searchService =
          new SearchServiceImpl(session, new StubAnalysisService(), new MemoryServiceImpl(session));

      StringSearchResult defaultResult = searchService.searchStrings(allStringsQuery(null, null));
      assertTrue(defaultResult.indexComplete());
      assertEquals(1, defaultResult.totalIndexed());
      assertEquals(1, defaultResult.page().items().size());
      StringMatchResource match = defaultResult.page().items().getFirst();
      assertEquals("WideElfSymbolPayload", match.value());
      assertEquals(StringMatchResource.Encoding.UTF16LE, match.encoding());
      assertFalse(match.defined());
    }
  }

  private static StringSearchQuery allStringsQuery(String query, String regex) {
    return new StringSearchQuery(
        AddressScanOptions.of(null, null, 5000),
        100,
        null,
        query,
        regex,
        EncodingFilter.ALL,
        null,
        null,
        false);
  }

  private static void writeNullTerminated(
      byte[] dest, int offset, byte[] content, int terminatorBytes) {
    System.arraycopy(content, 0, dest, offset, content.length);
    for (int i = 0; i < terminatorBytes; i++) {
      dest[offset + content.length + i] = 0;
    }
  }

  private static final class StubAnalysisService implements AnalysisService {
    final AtomicBoolean running = new AtomicBoolean(false);

    @Override
    public AnalysisResource startAnalysis(List<String> analyzers) {
      throw new UnsupportedOperationException();
    }

    @Override
    public AnalysisResource getStatus() {
      return new AnalysisResource(
          AnalysisResource.Kind.BRIDGE,
          running.get() ? AnalysisResource.Status.RUNNING : AnalysisResource.Status.IDLE,
          !running.get(),
          null,
          null,
          null,
          null);
    }

    @Override
    public void close() {}
  }

  private static final class ScanSpy {
    final AtomicInteger listingCalls = new AtomicInteger();
    final AtomicInteger memoryReadCalls = new AtomicInteger();

    void reset() {
      listingCalls.set(0);
      memoryReadCalls.set(0);
    }

    Program wrap(Program delegate) {
      Listing realListing = delegate.getListing();
      Memory realMemory = delegate.getMemory();

      Listing listingProxy =
          (Listing)
              Proxy.newProxyInstance(
                  Listing.class.getClassLoader(),
                  new Class<?>[] {Listing.class},
                  (proxy, method, args) -> {
                    if ("getDefinedData".equals(method.getName())
                        || "getUndefinedRanges".equals(method.getName())
                        || "getDataAt".equals(method.getName())) {
                      listingCalls.incrementAndGet();
                    }
                    try {
                      return method.invoke(realListing, args);
                    } catch (InvocationTargetException error) {
                      throw error.getTargetException();
                    }
                  });

      Memory memoryProxy =
          (Memory)
              Proxy.newProxyInstance(
                  Memory.class.getClassLoader(),
                  new Class<?>[] {Memory.class},
                  (proxy, method, args) -> {
                    if ("getBytes".equals(method.getName())) {
                      memoryReadCalls.incrementAndGet();
                    }
                    try {
                      return method.invoke(realMemory, args);
                    } catch (InvocationTargetException error) {
                      throw error.getTargetException();
                    }
                  });

      return (Program)
          Proxy.newProxyInstance(
              Program.class.getClassLoader(),
              new Class<?>[] {Program.class},
              (proxy, method, args) -> {
                if ("getListing".equals(method.getName())) return listingProxy;
                if ("getMemory".equals(method.getName())) return memoryProxy;
                try {
                  return method.invoke(delegate, args);
                } catch (InvocationTargetException error) {
                  throw error.getTargetException();
                }
              });
    }
  }
}
