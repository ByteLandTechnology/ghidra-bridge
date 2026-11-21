package app.byteland.ghidra.adapter.ghidra.memory;

import java.io.ByteArrayOutputStream;

/**
 * Parses and matches hexadecimal byte patterns with {@code ?} and {@code ??} wildcards.
 */
final class WildcardBytePattern {
  static final int MAX_PATTERN_BYTES = 4096;

  private final byte[] expected;
  private final byte[] masks;

  private WildcardBytePattern(byte[] expected, byte[] masks) {
    this.expected = expected;
    this.masks = masks;
  }

  static WildcardBytePattern parse(String rawPattern) {
    if (rawPattern == null || rawPattern.isBlank()) {
      throw new IllegalArgumentException("pattern must not be blank");
    }
    String trimmed = rawPattern.trim();
    String[] tokens = trimmed.split("[\\s,_-]+");
    ByteArrayOutputStream expectedOut = new ByteArrayOutputStream();
    ByteArrayOutputStream masksOut = new ByteArrayOutputStream();
    boolean hasFixedNibble = false;

    for (String rawToken : tokens) {
      if (rawToken.isEmpty()) continue;
      String token = rawToken;
      if (token.length() > 2 && (token.startsWith("0x") || token.startsWith("0X"))) {
        token = token.substring(2);
      }
      if ("?".equals(token)) {
        appendByte(expectedOut, masksOut, 0, 0);
        continue;
      }
      if ((token.length() & 1) != 0) {
        throw new IllegalArgumentException(
            "pattern token must have an even number of nibbles: " + rawToken);
      }
      for (int index = 0; index < token.length(); index += 2) {
        char high = token.charAt(index);
        char low = token.charAt(index + 1);
        int highValue = parseNibble(high, rawToken);
        int lowValue = parseNibble(low, rawToken);
        int expectedByte = ((highValue < 0 ? 0 : highValue) << 4) | (lowValue < 0 ? 0 : lowValue);
        int maskByte = (highValue < 0 ? 0 : 0xF0) | (lowValue < 0 ? 0 : 0x0F);
        if (maskByte != 0) {
          hasFixedNibble = true;
        }
        appendByte(expectedOut, masksOut, expectedByte, maskByte);
      }
    }

    int byteCount = expectedOut.size();
    if (byteCount == 0) {
      throw new IllegalArgumentException("pattern must contain at least one byte");
    }
    if (byteCount > MAX_PATTERN_BYTES) {
      throw new IllegalArgumentException(
          "pattern exceeds maximum length of " + MAX_PATTERN_BYTES + " bytes");
    }
    if (!hasFixedNibble) {
      throw new IllegalArgumentException("pattern must include at least one fixed hex digit");
    }
    return new WildcardBytePattern(expectedOut.toByteArray(), masksOut.toByteArray());
  }

  int length() {
    return expected.length;
  }

  boolean matchesAt(byte[] buffer, int offset) {
    for (int index = 0; index < expected.length; index++) {
      if ((buffer[offset + index] & masks[index]) != expected[index]) {
        return false;
      }
    }
    return true;
  }

  private static void appendByte(
      ByteArrayOutputStream expectedOut,
      ByteArrayOutputStream masksOut,
      int expectedByte,
      int maskByte) {
    if (expectedOut.size() >= MAX_PATTERN_BYTES + 1) {
      throw new IllegalArgumentException(
          "pattern exceeds maximum length of " + MAX_PATTERN_BYTES + " bytes");
    }
    expectedOut.write(expectedByte);
    masksOut.write(maskByte);
  }

  private static int parseNibble(char ch, String token) {
    if (ch == '?') return -1;
    int digit = Character.digit(ch, 16);
    if (digit < 0) {
      throw new IllegalArgumentException("invalid hex or wildcard character in pattern: " + token);
    }
    return digit;
  }
}
