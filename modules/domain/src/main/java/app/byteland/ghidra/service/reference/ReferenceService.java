package app.byteland.ghidra.service.reference;

import app.byteland.ghidra.service.Page;

/**
 * Searches code and data references across the program.
 */
@FunctionalInterface
public interface ReferenceService {
  /**
   * Returns one page of memory references that match the filter criteria.
   *
   * @param fromRaw optional source address filter
   * @param toRaw optional destination address filter
   * @param type optional reference type filter
   * @param direction optional query direction ({@code from} or {@code to})
   * @param limit maximum items per page
   * @param cursor pagination cursor, or {@code null}
   * @return page of matching references
   */
  Page<ReferenceResource> listReferences(
      String fromRaw, String toRaw, String type, String direction, int limit, String cursor);
}
