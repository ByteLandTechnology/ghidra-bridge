package app.byteland.ghidra.service.reference;

import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.Page;

/**
 * Searches code and data references across the program.
 */
@FunctionalInterface
public interface ReferenceService {
  /**
   * Returns one page of memory references that match the filter criteria.
   */
  Page<ReferenceResource> listReferences(
      String fromRaw, String toRaw, String type, String direction, int limit, String cursor);

  /**
   * Returns one page of target references with call sites and caller summaries.
   */
  default Page<ReferenceContextResource> listReferenceContext(
      String toRaw,
      String entryRaw,
      String symbolIdRaw,
      String type,
      AddressScanOptions scan,
      int limit,
      String cursor) {
    throw new UnsupportedOperationException("listReferenceContext");
  }
}
