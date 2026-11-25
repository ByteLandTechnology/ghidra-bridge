package app.byteland.ghidra.service.search;

import java.util.ArrayList;
import java.util.List;

/**
 * Compiled byte pattern with per-nibble wildcard masks.
 */
public final class WildcardBytePattern {
  public static final int MAX_PATTERN_BYTES = 256;

  private final int index;
  private final String rawPattern;
  private final byte[] expected;
  private final byte[] masks;

  private WildcardBytePattern(int index, String rawPattern, byte[] expected, byte[] masks) {
    this.index = index;
    this.rawPattern = rawPattern;
    this.expected = expected;
    this.masks = masks;
  }

  /**
   * Parses a hex pattern string with {@code ??} or single-nibble {@code ?} wildcards.
   */
  public static WildcardBytePattern parse(int index, String rawPattern) {
    if (rawPattern == null || rawPattern.isBlank()) {
      throw new IllegalArgumentException("byte pattern must not be blank");
    }
    String trimmed = rawPattern.trim();
    List<Byte> expectedBytes = new ArrayList<>();
    List<Byte> maskBytes = new ArrayList<>();

    if (containsWhitespace(trimmed)) {
      String[] tokens = trimmed.split("\\s+");
      for (String token : tokens) {
        parseEvenToken(token, expectedBytes, maskBytes);
      }
    } else {
      parseEvenToken(trimmed, expectedBytes, maskBytes);
    }

    if (expectedBytes.isEmpty()) {
      throw new IllegalArgumentException("byte pattern must contain at least 1 byte");
    }
    if (expectedBytes.size() > MAX_PATTERN_BYTES) {
      throw new IllegalArgumentException(
          "byte pattern exceeds maximum length of " + MAX_PATTERN_BYTES + " bytes");
    }

    byte[] expected = new byte[expectedBytes.size()];
    byte[] masks = new byte[maskBytes.size()];
    for (int i = 0; i < expected.length; i++) {
      expected[i] = expectedBytes.get(i);
      masks[i] = maskBytes.get(i);
    }
    return new WildcardBytePattern(index, rawPattern, expected, masks);
  }

  public int index() {
    return index;
  }

  public String rawPattern() {
    return rawPattern;
  }

  public int byteLength() {
    return expected.length;
  }

  public boolean matches(byte[] buffer, int offset, int validLength) {
    int length = expected.length;
    if (offset < 0 || offset + length > validLength) {
      return false;
    }
    for (int i = 0; i < length; i++) {
      if ((buffer[offset + i] & masks[i]) != expected[i]) {
        return false;
      }
    }
    return true;
  }

  private static boolean containsWhitespace(String text) {
    for (int i = 0; i < text.length(); i++) {
      if (Character.isWhitespace(text.charAt(i))) {
        return true;
      }
    }
    return false;
  }

  private static void parseEvenToken(
      String rawToken, List<Byte> expectedBytes, List<Byte> maskBytes) {
    String token = rawToken;
    if ((token.startsWith("0x") || token.startsWith("0X")) && token.length() >= 4) {
      token = token.substring(2);
    } else if ((token.startsWith("0x") || token.startsWith("0X")) && token.length() == 4) {
      token = token.substring(2);
    }
    if (token.isEmpty() || (token.length() & 1) != 0) {
      throw new IllegalArgumentException(
          "byte pattern token must have an even number of hex or '?' characters: " + rawToken);
    }
    for (int pos = 0; pos < token.length(); pos += 2) {
      char hi = token.charAt(pos);
      char lo = token.charAt(pos + 1);
      int expected = 0;
      int mask = 0;
      if (hi != '?') {
        int hiDigit = hexDigit(hi, rawToken);
        expected |= (hiDigit << 4);
        mask |= 0xF0;
      }
      if (lo != '?') {
        int loDigit = hexDigit(lo, rawToken);
        expected |= loDigit;
        mask |= 0x0F;
      }
      expectedBytes.add((byte) expected);
      maskBytes.add((byte) mask);
    }
  }

  private static int hexDigit(char ch, String context) {
    int digit = Character.digit(ch, 16);
    if (digit < 0) {
      throw new IllegalArgumentException(
          "invalid character '" + ch + "' in byte pattern: " + context);
    }
    return digit;
  }
}
