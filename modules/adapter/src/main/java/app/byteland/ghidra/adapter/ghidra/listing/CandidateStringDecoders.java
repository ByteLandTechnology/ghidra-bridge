package app.byteland.ghidra.adapter.ghidra.listing;

import java.nio.charset.StandardCharsets;

/**
 * Decodes candidate UTF-16, ASCII, and UTF-8 string runs from initialized byte buffers.
 */
final class CandidateStringDecoders {
  static final int MAX_CANDIDATE_BYTES = 8_192;

  private CandidateStringDecoders() {}

  record CandidateMatch(String value, int byteLength, String encoding, String dataTypeName) {}

  static CandidateMatch tryDecodeUtf16(
      byte[] buf, int start, int limit, int minCandidateLen, boolean programBigEndian) {
    if (start + 1 >= limit) {
      return null;
    }
    int b0 = buf[start] & 0xFF;
    int b1 = buf[start + 1] & 0xFF;
    if (isPrintableAscii(b0) && b1 == 0) {
      int minRequired =
          programBigEndian ? Math.max(minCandidateLen, 4) : Math.max(minCandidateLen, 2);
      return decodeUtf16AsciiRun(buf, start, limit, minRequired, false);
    }
    if (b0 == 0 && isPrintableAscii(b1)) {
      int minRequired =
          programBigEndian ? Math.max(minCandidateLen, 2) : Math.max(minCandidateLen, 4);
      return decodeUtf16AsciiRun(buf, start, limit, minRequired, true);
    }
    return null;
  }

  private static CandidateMatch decodeUtf16AsciiRun(
      byte[] buf, int start, int limit, int minRequired, boolean bigEndian) {
    int maxEnd = Math.min(limit, start + MAX_CANDIDATE_BYTES);
    StringBuilder chars = new StringBuilder();
    int pos = start;
    while (pos + 1 < maxEnd) {
      int high = buf[pos] & 0xFF;
      int low = buf[pos + 1] & 0xFF;
      int codeUnit = bigEndian ? ((high << 8) | low) : ((low << 8) | high);
      if (!isPrintableAscii(codeUnit)) {
        break;
      }
      chars.append((char) codeUnit);
      pos += 2;
    }
    if (chars.length() < minRequired) {
      return null;
    }
    if (pos + 1 < limit && buf[pos] == 0 && buf[pos + 1] == 0) {
      pos += 2;
    }
    return new CandidateMatch(
        chars.toString(), pos - start, bigEndian ? "UTF-16BE" : "UTF-16LE", "unicode");
  }

  static CandidateMatch tryDecodeAsciiOrUtf8(
      byte[] buf, int start, int limit, int minCandidateLen) {
    int maxEnd = Math.min(limit, start + MAX_CANDIDATE_BYTES);
    int pos = start;
    int charCount = 0;
    boolean hasMultibyteUtf8 = false;

    while (pos < maxEnd) {
      int b0 = buf[pos] & 0xFF;
      if (b0 < 0x80) {
        if (!isPrintableAscii(b0)) {
          break;
        }
        // Stop before a UTF-16LE sequence of two or more printable characters.
        if (pos > start
            && pos + 3 < maxEnd
            && buf[pos + 1] == 0
            && isPrintableAscii(buf[pos + 2] & 0xFF)
            && buf[pos + 3] == 0) {
          break;
        }
        pos += 1;
        charCount += 1;
        continue;
      }
      int utf8Bytes = decodePrintableUtf8SequenceLength(buf, pos, maxEnd);
      if (utf8Bytes <= 0) {
        break;
      }
      hasMultibyteUtf8 = true;
      pos += utf8Bytes;
      charCount += 1;
    }

    if (charCount < minCandidateLen) {
      return null;
    }
    String value = new String(buf, start, pos - start, StandardCharsets.UTF_8);
    if (value.length() < minCandidateLen) {
      return null;
    }
    int byteLength = pos - start;
    if (pos < limit && buf[pos] == 0) {
      byteLength += 1;
    }
    return new CandidateMatch(
        value,
        byteLength,
        hasMultibyteUtf8 ? "UTF-8" : "US-ASCII",
        hasMultibyteUtf8 ? "utf8" : "string");
  }

  static int skipNonMatchingAsciiRun(byte[] buf, int start, int limit) {
    if (!isPrintableAscii(buf[start] & 0xFF)) {
      return 1;
    }
    if (start + 1 < limit && buf[start + 1] == 0) {
      return 1;
    }
    int pos = start + 1;
    while (pos < limit && isPrintableAscii(buf[pos] & 0xFF)) {
      if (pos + 1 < limit && buf[pos + 1] == 0) {
        break;
      }
      pos++;
    }
    return pos - start;
  }

  private static int decodePrintableUtf8SequenceLength(byte[] buf, int pos, int limit) {
    int b0 = buf[pos] & 0xFF;
    int needed;
    int codePoint;
    int minCodePoint;
    if (b0 >= 0xC2 && b0 <= 0xDF) {
      needed = 2;
      codePoint = b0 & 0x1F;
      minCodePoint = 0x80;
    } else if (b0 >= 0xE0 && b0 <= 0xEF) {
      needed = 3;
      codePoint = b0 & 0x0F;
      minCodePoint = 0x800;
    } else if (b0 >= 0xF0 && b0 <= 0xF4) {
      needed = 4;
      codePoint = b0 & 0x07;
      minCodePoint = 0x10000;
    } else {
      return 0;
    }
    if (pos + needed > limit) {
      return 0;
    }
    for (int i = 1; i < needed; i++) {
      int cont = buf[pos + i] & 0xFF;
      if ((cont & 0xC0) != 0x80) {
        return 0;
      }
      codePoint = (codePoint << 6) | (cont & 0x3F);
    }
    if (codePoint < minCodePoint
        || codePoint > 0x10FFFF
        || (codePoint >= 0xD800 && codePoint <= 0xDFFF)) {
      return 0;
    }
    if (Character.isISOControl(codePoint)) {
      return 0;
    }
    int type = Character.getType(codePoint);
    if (type == Character.UNASSIGNED
        || type == Character.PRIVATE_USE
        || type == Character.SURROGATE) {
      return 0;
    }
    return needed;
  }

  private static boolean isPrintableAscii(int ch) {
    return (ch >= 0x20 && ch <= 0x7E) || ch == '\t' || ch == '\n' || ch == '\r';
  }
}
