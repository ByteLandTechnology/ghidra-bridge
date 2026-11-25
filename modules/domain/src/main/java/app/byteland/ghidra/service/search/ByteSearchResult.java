package app.byteland.ghidra.service.search;

import app.byteland.ghidra.service.ScanProgress;
import java.util.List;
import java.util.Objects;

/**
 * Holds grouped byte pattern matches, pagination cursor, and scan progress.
 */
public record ByteSearchResult(
    List<BytePatternMatchesResource> items,
    int totalMatches,
    String nextCursor,
    ScanProgress scan) {
  public ByteSearchResult {
    items = List.copyOf(Objects.requireNonNull(items, "items"));
    Objects.requireNonNull(scan, "scan");
    if (totalMatches < 0) {
      throw new IllegalArgumentException("totalMatches must not be negative");
    }
  }
}
