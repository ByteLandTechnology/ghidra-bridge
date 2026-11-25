package app.byteland.ghidra.service.search;

import app.byteland.ghidra.service.datatype.DataTypeReference;
import java.util.Objects;

/**
 * Represents a decoded string entry from defined data or undefined initialized bytes.
 */
public record StringMatchResource(
    String address,
    String value,
    int length,
    Encoding encoding,
    boolean defined,
    DataTypeReference dataType) {
  public StringMatchResource {
    Objects.requireNonNull(address, "address");
    Objects.requireNonNull(value, "value");
    Objects.requireNonNull(encoding, "encoding");
    if (length < 0) throw new IllegalArgumentException("length must not be negative");
  }

  /**
   * Character encoding of a decoded string entry.
   */
  public enum Encoding {
    ASCII,
    UTF16LE,
    UTF16BE
  }
}
