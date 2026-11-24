package app.byteland.ghidra.service.reference;

import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.listing.FlowOverrideScope;

/**
 * Searches code and data references across the program.
 */
@FunctionalInterface
public interface ReferenceService {
  /**
   * Filter and pagination options for reference list queries.
   */
  record ReferenceQuery(
      FlowOverrideScope selector,
      String from,
      String to,
      String type,
      String direction,
      AddressScanOptions scan,
      int limit,
      String cursor) {
    public ReferenceQuery {
      if (scan == null) throw new IllegalArgumentException("scan is required");
      if (limit < 1 || limit > Page.MAX_LIMIT) {
        throw new IllegalArgumentException("limit must be in 1.." + Page.MAX_LIMIT);
      }
    }
  }

  /**
   * Returns one page of memory references that match the query.
   */
  Page<ReferenceResource> listReferences(ReferenceQuery query);

  /**
   * Returns one page of memory references that match single-address filters.
   */
  default Page<ReferenceResource> listReferences(
      String fromRaw, String toRaw, String type, String direction, int limit, String cursor) {
    return listReferences(
        new ReferenceQuery(
            null,
            fromRaw,
            toRaw,
            type,
            direction,
            new AddressScanOptions(null, null, AddressScanOptions.DEFAULT_TIMEOUT_MS),
            limit,
            cursor));
  }
}
