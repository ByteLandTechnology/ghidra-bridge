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
   * Returns one page of references that match the filter and scan bounds.
   */
  Page<ReferenceResource> listReferences(
      String fromRaw,
      String toRaw,
      String type,
      String direction,
      FlowOverrideScope scope,
      AddressScanOptions scan,
      int limit,
      String cursor);

  /**
   * Returns one page of references for a single anchor with default scan bounds.
   */
  default Page<ReferenceResource> listReferences(
      String fromRaw, String toRaw, String type, String direction, int limit, String cursor) {
    return listReferences(
        fromRaw,
        toRaw,
        type,
        direction,
        null,
        new AddressScanOptions(null, null, AddressScanOptions.DEFAULT_TIMEOUT_MS),
        limit,
        cursor);
  }
}
