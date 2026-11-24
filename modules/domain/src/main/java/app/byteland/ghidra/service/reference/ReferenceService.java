package app.byteland.ghidra.service.reference;

import app.byteland.ghidra.service.Page;

/**
 * Searches code and data references across the program.
 */
@FunctionalInterface
public interface ReferenceService {
  /**
   * Inclusive start and end addresses for a source reference scan.
   *
   * @param start start address text
   * @param end end address text
   */
  record RangeFilter(String start, String end) {}

  /**
   * Returns one page of memory references that match the filter criteria.
   */
  Page<ReferenceResource> listReferences(
      String fromRaw,
      String entryRaw,
      RangeFilter fromRange,
      String toRaw,
      String type,
      String direction,
      int limit,
      String cursor);

  /**
   * Returns one page of memory references from or to a single address.
   */
  default Page<ReferenceResource> listReferences(
      String fromRaw, String toRaw, String type, String direction, int limit, String cursor) {
    return listReferences(fromRaw, null, null, toRaw, type, direction, limit, cursor);
  }
}
