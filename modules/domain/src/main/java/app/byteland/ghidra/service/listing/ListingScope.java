package app.byteland.ghidra.service.listing;

/**
 * Selects one address or an inclusive address range in the program listing.
 */
public sealed interface ListingScope
    permits ListingScope.AddressScope, ListingScope.RangeScope {
  String kind();

  record AddressScope(String address) implements ListingScope {
    @Override
    public String kind() {
      return "address";
    }
  }

  record RangeScope(String start, String end) implements ListingScope {
    @Override
    public String kind() {
      return "range";
    }
  }
}
