package app.byteland.ghidra.adapter.ghidra.listing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.adapter.ghidra.GhidraTestSupport;
import app.byteland.ghidra.adapter.ghidra.GhidraTestSupport.ProgramHolder;
import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.ScanProgress;
import app.byteland.ghidra.service.listing.ListingService.StringQuery;
import app.byteland.ghidra.service.listing.StringResource;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.data.TerminatedUnicodeDataType;
import ghidra.program.model.data.Undefined;
import ghidra.util.task.TaskMonitor;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;

class ListingStringQueriesTest {

  @Test
  void listsDefinedStringsResumesInsideStructAndMergesCandidateScans() {
    try (ProgramHolder holder = GhidraTestSupport.createX64Program("strings_test")) {
      holder.inTransaction(
          program -> {
            AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
            Address base = space.getAddress(0x4000L);

            ByteArrayOutputStream raw = new ByteArrayOutputStream();
            // 0x4000..0x400c: raw undefined ASCII candidate ("alpha_secret\0", 13 bytes)
            raw.write("alpha_secret\0".getBytes(StandardCharsets.US_ASCII));
            padTo(raw, 0x20);
            // 0x4020..0x4031: defined `TerminatedString` ("https://svc.test\0", 17 bytes)
            raw.write("https://svc.test\0".getBytes(StandardCharsets.US_ASCII));
            padTo(raw, 0x40);
            // 0x4040..0x4053: struct with two 10-byte `StringDataType` fields
            raw.write("field_one\0".getBytes(StandardCharsets.US_ASCII));
            raw.write("field_two\0".getBytes(StandardCharsets.US_ASCII));
            padTo(raw, 0x60);
            // 0x4060..0x4073: undefined placeholder array around UTF-8 candidate
            raw.write(new byte[] {(byte) 0xfe, (byte) 0xff});
            raw.write("caf\u00e9_token\0".getBytes(StandardCharsets.UTF_8));
            raw.write(new byte[] {(byte) 0xfd, (byte) 0xfc});
            padTo(raw, 0x80);
            // 0x4080..0x4091: defined UTF-16LE string ("wide_str\0", 18 bytes)
            raw.write("wide_str\0".getBytes(StandardCharsets.UTF_16LE));
            padTo(raw, 0xa0);
            // 0x40a0..0x40af: candidate UTF-16LE string ("cand_w\0", 14 bytes)
            raw.write("cand_w\0".getBytes(StandardCharsets.UTF_16LE));
            padTo(raw, 0xc0);

            byte[] bytes = raw.toByteArray();
            program
                .getMemory()
                .createInitializedBlock(
                    ".rodata",
                    base,
                    new ByteArrayInputStream(bytes),
                    bytes.length,
                    TaskMonitor.DUMMY,
                    false);

            DataUtilities.createData(
                program,
                space.getAddress(0x4020L),
                TerminatedStringDataType.dataType,
                -1,
                false,
                ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);

            StructureDataType pairStruct = new StructureDataType("StringPair", 0);
            pairStruct.add(StringDataType.dataType, 10, "first", null);
            pairStruct.add(StringDataType.dataType, 10, "second", null);
            DataUtilities.createData(
                program,
                space.getAddress(0x4040L),
                pairStruct,
                -1,
                false,
                ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);

            DataUtilities.createData(
                program,
                space.getAddress(0x4060L),
                Undefined.getUndefinedDataType(18),
                -1,
                false,
                ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);

            DataUtilities.createData(
                program,
                space.getAddress(0x4080L),
                TerminatedUnicodeDataType.dataType,
                -1,
                false,
                ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);

            program
                .getMemory()
                .createUninitializedBlock(".bss", space.getAddress(0x5000L), 0x400L, false);
          });

      ListingStringQueries queries =
          new ListingStringQueries(GhidraTestSupport.sessionFor(holder.program()));
      AddressScanOptions range = AddressScanOptions.of("ram:00004000", "ram:000053ff", 2_000);

      // Defined-only scan omits raw undefined and placeholder-wrapped candidates.
      Page<StringResource> definedOnly =
          queries.listStrings(
              new StringQuery(range, null, null, false, null, null, false, 20, null));
      assertEquals(
          List.of("https://svc.test", "field_one", "field_two", "wide_str"),
          definedOnly.items().stream().map(StringResource::value).toList());
      assertTrue(definedOnly.items().stream().allMatch(StringResource::defined));
      assertEquals("UTF-16LE", definedOnly.items().get(3).encoding());

      // Cursor inside composite struct resumes at the second nested field without loss.
      Page<StringResource> resumedInStruct =
          queries.listStrings(
              new StringQuery(range, null, null, false, null, null, false, 20, "ram:00004040"));
      assertEquals(
          List.of("field_two", "wide_str"),
          resumedInStruct.items().stream().map(StringResource::value).toList());

      // Candidate scan merges candidates and defined strings across single-item pages.
      List<String> expectedValues =
          List.of(
              "alpha_secret",
              "https://svc.test",
              "field_one",
              "field_two",
              "caf\u00e9_token",
              "wide_str",
              "cand_w");
      List<Boolean> expectedDefined = List.of(false, true, true, true, false, true, false);
      String cursor = null;
      for (int index = 0; index < expectedValues.size(); index++) {
        Page<StringResource> page =
            queries.listStrings(
                new StringQuery(range, null, null, false, null, null, true, 1, cursor));
        assertEquals(1, page.items().size());
        StringResource item = page.items().getFirst();
        assertEquals(expectedValues.get(index), item.value());
        assertEquals(expectedDefined.get(index), item.defined());
        assertEquals(ScanProgress.StopReason.LIMIT, page.scanProgress().stopReason());
        assertNotNull(page.nextCursor());
        cursor = page.nextCursor();
      }
      Page<StringResource> finalEmptyPage =
          queries.listStrings(
              new StringQuery(range, null, null, false, null, null, true, 1, cursor));
      assertTrue(finalEmptyPage.items().isEmpty());
      assertTrue(finalEmptyPage.scanProgress().complete());
      assertNull(finalEmptyPage.nextCursor());

      Page<StringResource> fullCandidatePage =
          queries.listStrings(
              new StringQuery(range, null, null, false, null, null, true, 20, null));
      assertEquals(
          expectedValues, fullCandidatePage.items().stream().map(StringResource::value).toList());
      assertEquals("UTF-8", fullCandidatePage.items().get(4).encoding());
      assertFalse(fullCandidatePage.items().get(4).defined());
    }
  }

  @Test
  void normalizesCharsetsAndDecodesUtf16AndUtf8Slices() {
    assertEquals("US-ASCII", DefinedStringStream.normalizeDefinedCharset(null, false));
    assertEquals("UTF-16LE", DefinedStringStream.normalizeDefinedCharset("UTF-16", false));
    assertEquals("UTF-16BE", DefinedStringStream.normalizeDefinedCharset("UTF-16", true));
    assertEquals("UTF-32LE", DefinedStringStream.normalizeDefinedCharset("UTF-32", false));
    assertEquals("UTF-32BE", DefinedStringStream.normalizeDefinedCharset("UTF-32", true));

    byte[] utf16Be = "be_text\0".getBytes(StandardCharsets.UTF_16BE);
    CandidateStringDecoders.CandidateMatch beMatch =
        CandidateStringDecoders.tryDecodeUtf16(utf16Be, 0, utf16Be.length, 4, true);
    assertNotNull(beMatch);
    assertEquals("be_text", beMatch.value());
    assertEquals("UTF-16BE", beMatch.encoding());
    assertEquals(16, beMatch.byteLength());

    byte[] shortAscii = "ab\u0001xyz".getBytes(StandardCharsets.US_ASCII);
    assertNull(CandidateStringDecoders.tryDecodeAsciiOrUtf8(shortAscii, 0, shortAscii.length, 4));
    assertEquals(
        2, CandidateStringDecoders.skipNonMatchingAsciiRun(shortAscii, 0, shortAscii.length));

    byte[] beforeUtf16Le = "ab\0c\0".getBytes(StandardCharsets.US_ASCII);
    assertEquals(
        1, CandidateStringDecoders.skipNonMatchingAsciiRun(beforeUtf16Le, 0, beforeUtf16Le.length));
  }

  private static void padTo(ByteArrayOutputStream out, int size) {
    while (out.size() < size) {
      out.write(0xff);
    }
  }
}
