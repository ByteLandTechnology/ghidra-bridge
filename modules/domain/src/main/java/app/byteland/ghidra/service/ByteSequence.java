package app.byteland.ghidra.service;

/**
 * Holds raw byte data and its transfer encoding.
 *
 * @param encoding wire encoding format
 * @param data encoded byte string data
 * @param length byte length of decoded sequence
 */
public record ByteSequence(Encoding encoding, String data, int length) {
  /** Validates that {@code encoding} and {@code data} are non-null and {@code length >= 0}. */
  public ByteSequence {
    if (encoding == null) throw new IllegalArgumentException("encoding is required");
    if (data == null) throw new IllegalArgumentException("data is required");
    if (length < 0) throw new IllegalArgumentException("length must be non-negative");
  }

  /**
   * Supported wire formats for byte transfer.
   */
  public enum Encoding {
    /** Lowercase hexadecimal byte string. */
    HEX,
    /** Standard RFC 4648 Base64 byte string. */
    BASE64
  }
}
