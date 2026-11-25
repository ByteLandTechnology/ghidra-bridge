package app.byteland.ghidra.service.search;

import app.byteland.ghidra.service.Page;
import java.util.Objects;

/**
 * Holds one page of string search items and cache completeness metadata.
 */
public record StringSearchResult(
    Page<StringMatchResource> page,
    boolean indexComplete,
    int totalIndexed,
    long modificationNumber) {
  public StringSearchResult {
    Objects.requireNonNull(page, "page");
    if (totalIndexed < 0) {
      throw new IllegalArgumentException("totalIndexed must not be negative");
    }
  }
}
