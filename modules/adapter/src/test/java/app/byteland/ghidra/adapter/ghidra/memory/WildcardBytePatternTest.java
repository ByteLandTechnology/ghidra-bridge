package app.byteland.ghidra.adapter.ghidra.memory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class WildcardBytePatternTest {
  @Test
  void matchesExactAndWildcardPatterns() {
    WildcardBytePattern exact = WildcardBytePattern.parse("48 8B 05 12 34");
    assertEquals(5, exact.length());
    assertTrue(exact.matchesAt(new byte[] {0x48, (byte) 0x8B, 0x05, 0x12, 0x34}, 0));
    assertFalse(exact.matchesAt(new byte[] {0x48, (byte) 0x8B, 0x06, 0x12, 0x34}, 0));

    WildcardBytePattern fullByteWildcard = WildcardBytePattern.parse("48 8b ?? ? 90");
    assertEquals(5, fullByteWildcard.length());
    assertTrue(
        fullByteWildcard.matchesAt(
            new byte[] {0x00, 0x48, (byte) 0x8B, (byte) 0xAA, 0x55, (byte) 0x90}, 1));

    WildcardBytePattern halfByteWildcard = WildcardBytePattern.parse("0x4? ?F,90_CC");
    assertEquals(4, halfByteWildcard.length());
    assertTrue(
        halfByteWildcard.matchesAt(
            new byte[] {0x4A, (byte) 0xBF, (byte) 0x90, (byte) 0xCC}, 0));
    assertFalse(
        halfByteWildcard.matchesAt(
            new byte[] {0x5A, (byte) 0xBF, (byte) 0x90, (byte) 0xCC}, 0));
  }

  @Test
  void rejectsInvalidAndAllWildcardPatterns() {
    assertThrows(IllegalArgumentException.class, () -> WildcardBytePattern.parse(null));
    assertThrows(IllegalArgumentException.class, () -> WildcardBytePattern.parse("   "));
    assertThrows(IllegalArgumentException.class, () -> WildcardBytePattern.parse("?? ??"));
    assertThrows(IllegalArgumentException.class, () -> WildcardBytePattern.parse("? ?? ????"));
    assertThrows(IllegalArgumentException.class, () -> WildcardBytePattern.parse("48 8"));
    assertThrows(IllegalArgumentException.class, () -> WildcardBytePattern.parse("48 ZZ"));
    String overLimit = "AA ".repeat(WildcardBytePattern.MAX_PATTERN_BYTES + 1);
    assertThrows(IllegalArgumentException.class, () -> WildcardBytePattern.parse(overLimit));
  }
}
