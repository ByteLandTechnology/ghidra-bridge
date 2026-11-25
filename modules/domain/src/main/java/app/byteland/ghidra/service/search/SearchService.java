package app.byteland.ghidra.service.search;

import app.byteland.ghidra.service.AddressScanOptions;
import java.util.List;
import java.util.Objects;

/**
 * Searches cached program strings and scans initialized memory for byte patterns.
 */
public interface SearchService {
  int MAX_BYTE_PATTERNS = 100;
  int DEFAULT_MAX_STRING_ENTRIES = 100_000;
  int DEFAULT_MAX_STRING_BYTES = 4_096;

  /**
   * Query parameters for string search operations.
   */
  record StringSearchQuery(
      AddressScanOptions scan,
      int limit,
      String cursor,
      String query,
      String regex,
      EncodingFilter encoding,
      Boolean defined,
      Integer minLength,
      boolean caseSensitive) {
    public StringSearchQuery {
      Objects.requireNonNull(scan, "scan");
      if (limit < 1 || limit > 1000) {
        throw new IllegalArgumentException("limit must be in 1..1000");
      }
      if (minLength != null && minLength < 1) {
        throw new IllegalArgumentException("minLength must be positive");
      }
    }
  }

  /**
   * Character encoding filter for string search queries.
   */
  enum EncodingFilter {
    ALL,
    ASCII,
    UTF16,
    UTF16LE,
    UTF16BE;

    public boolean matches(StringMatchResource.Encoding candidate) {
      return switch (this) {
        case ALL -> true;
        case ASCII -> candidate == StringMatchResource.Encoding.ASCII;
        case UTF16 ->
            candidate == StringMatchResource.Encoding.UTF16LE
                || candidate == StringMatchResource.Encoding.UTF16BE;
        case UTF16LE -> candidate == StringMatchResource.Encoding.UTF16LE;
        case UTF16BE -> candidate == StringMatchResource.Encoding.UTF16BE;
      };
    }
  }

  /**
   * Query parameters for batch wildcard byte pattern scans.
   */
  record ByteSearchQuery(
      AddressScanOptions scan, int limit, String cursor, List<String> patterns) {
    public ByteSearchQuery {
      Objects.requireNonNull(scan, "scan");
      patterns = List.copyOf(Objects.requireNonNull(patterns, "patterns"));
      if (limit < 1 || limit > 1000) {
        throw new IllegalArgumentException("limit must be in 1..1000");
      }
      if (patterns.isEmpty() || patterns.size() > MAX_BYTE_PATTERNS) {
        throw new IllegalArgumentException("patterns size must be in 1.." + MAX_BYTE_PATTERNS);
      }
    }
  }

  /**
   * Searches cached ASCII and UTF-16 strings with text or regex filters.
   */
  StringSearchResult searchStrings(StringSearchQuery query);

  /**
   * Scans initialized memory blocks for wildcard byte patterns.
   */
  ByteSearchResult searchBytes(ByteSearchQuery query);
}
