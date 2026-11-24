package app.byteland.ghidra.service.listing;

import java.util.Objects;

/**
 * Selects one address or an inclusive address range.
 */
public sealed interface AddressOrRangeScope {
  /**
   * Selects a single address.
   */
  record AddressScope(String address) implements AddressOrRangeScope {
    public AddressScope {
      Objects.requireNonNull(address, "address");
    }
  }

  /**
   * Selects an inclusive range from start to end.
   */
  record RangeScope(String start, String end) implements AddressOrRangeScope {
    public RangeScope {
      Objects.requireNonNull(start, "start");
      Objects.requireNonNull(end, "end");
    }
  }
}
