package app.byteland.ghidra.adapter.ghidra.memory;

import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Locale;

final class MemoryEncoding {
  private static final String BASE64_ENCODING = "base64";
  private static final String HEX_ENCODING = "hex";

  private MemoryEncoding() {}

  static String normalizeEncoding(String encoding) {
    return encoding == null ? HEX_ENCODING : encoding.toLowerCase(Locale.ROOT);
  }

  static String encodeBytes(byte[] bytes, String encoding, int read) {
    byte[] body = read < bytes.length ? Arrays.copyOf(bytes, read) : bytes;
    return BASE64_ENCODING.equals(encoding)
        ? Base64.getEncoder().encodeToString(body)
        : HexFormat.of().formatHex(body);
  }

  static byte[] decodeBytes(String body, String encoding) {
    String norm = normalizeEncoding(encoding);
    if (BASE64_ENCODING.equals(norm)) {
      return Base64.getDecoder().decode(body);
    }
    return HexFormat.of().parseHex(body == null ? "" : body.trim());
  }
}
