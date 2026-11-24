package app.byteland.ghidra.service.listing;

import java.util.Objects;

/**
 * Receipt for a cleared code unit range.
 */
public record CodeUnitClearReceipt(String start, String end, boolean cleared) {
  public CodeUnitClearReceipt {
    Objects.requireNonNull(start, "start");
    Objects.requireNonNull(end, "end");
  }
}
