package app.byteland.ghidra.adapter.ghidra.memory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.service.memory.MemoryService.EncodedText;
import app.byteland.ghidra.service.memory.MemoryService.HexPattern;
import app.byteland.ghidra.service.memory.MemoryService.MaskedBytes;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class MemorySearchQueriesTest {
  @Test
  void compilesHexPatternsWithByteAndNibbleWildcards() {
    var matcher = MemorySearchQueries.compile(new HexPattern("48 8B ?? 4? .F 0x90"));
    assertEquals(6, matcher.length());

    byte[] matching = new byte[] {(byte) 0x48, (byte) 0x8B, (byte) 0xC7, 0x4A, 0x1F, (byte) 0x90};
    assertTrue(matcher.matches(matching, 0));

    byte[] mismatchHi = new byte[] {(byte) 0x48, (byte) 0x8B, 0x00, 0x5A, 0x1F, (byte) 0x90};
    assertFalse(matcher.matches(mismatchHi, 0));

    byte[] mismatchLo = new byte[] {(byte) 0x48, (byte) 0x8B, 0x00, 0x4A, 0x1E, (byte) 0x90};
    assertFalse(matcher.matches(mismatchLo, 0));
  }

  @Test
  void rejectsMalformedHexPatterns() {
    assertThrows(
        IllegalArgumentException.class,
        () -> MemorySearchQueries.compile(new HexPattern("48 8")));
    assertThrows(
        IllegalArgumentException.class,
        () -> MemorySearchQueries.compile(new HexPattern("48 ZZ")));
    assertThrows(
        IllegalArgumentException.class,
        () -> MemorySearchQueries.compile(new HexPattern("   ")));
  }

  @Test
  void compilesMaskedBytesWithAndWithoutMask() {
    var exact = MemorySearchQueries.compile(new MaskedBytes("DE AD BE EF", null));
    assertTrue(
        exact.matches(
            new byte[] {0x00, (byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF}, 1));
    assertFalse(
        exact.matches(
            new byte[] {0x00, (byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEE}, 1));

    var masked = MemorySearchQueries.compile(new MaskedBytes("48 89 E5", "FF F8 FF"));
    assertTrue(masked.matches(new byte[] {0x48, (byte) 0x8F, (byte) 0xE5}, 0));
    assertFalse(masked.matches(new byte[] {0x48, (byte) 0x90, (byte) 0xE5}, 0));

    assertThrows(
        IllegalArgumentException.class,
        () -> MemorySearchQueries.compile(new MaskedBytes("48 89", "FF")));
  }

  @Test
  void compilesEncodedStringsAcrossCharsetsAndCaseModes() {
    byte[] utf8Sample = "prefix Hello_World! suffix".getBytes(StandardCharsets.UTF_8);
    var csUtf8 = MemorySearchQueries.compile(new EncodedText("Hello_World!", "utf-8", true));
    assertTrue(csUtf8.matches(utf8Sample, 7));
    assertFalse(
        csUtf8.matches("prefix hello_world! suffix".getBytes(StandardCharsets.UTF_8), 7));

    var ciUtf8 = MemorySearchQueries.compile(new EncodedText("hello_world!", "utf-8", false));
    assertTrue(ciUtf8.matches(utf8Sample, 7));
    // '[' (0x5B) and '{' (0x7B) differ by 0x20, so punctuation must not be case-folded.
    var bracket = MemorySearchQueries.compile(new EncodedText("[tag]", "ascii", false));
    assertFalse(bracket.matches("{TAG}".getBytes(StandardCharsets.US_ASCII), 0));
    assertTrue(bracket.matches("[TAG]".getBytes(StandardCharsets.US_ASCII), 0));

    byte[] utf16LeSample = "InitConfig".getBytes(StandardCharsets.UTF_16LE);
    var ciUtf16Le = MemorySearchQueries.compile(new EncodedText("initconfig", "utf-16le", false));
    assertEquals(utf16LeSample.length, ciUtf16Le.length());
    assertTrue(ciUtf16Le.matches(utf16LeSample, 0));

    byte[] utf16BeSample = "InitConfig".getBytes(StandardCharsets.UTF_16BE);
    var ciUtf16Be = MemorySearchQueries.compile(new EncodedText("INITCONFIG", "utf-16be", false));
    assertEquals(utf16BeSample.length, ciUtf16Be.length());
    assertTrue(ciUtf16Be.matches(utf16BeSample, 0));

    assertThrows(
        IllegalArgumentException.class,
        () -> MemorySearchQueries.compile(new EncodedText("λ", "ascii", true)));
    assertThrows(
        IllegalArgumentException.class,
        () -> MemorySearchQueries.compile(new EncodedText("hello", "ebcdic", true)));
  }
}
