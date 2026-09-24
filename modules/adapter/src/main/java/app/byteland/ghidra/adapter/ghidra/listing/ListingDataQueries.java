package app.byteland.ghidra.adapter.ghidra.listing;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.scan.AddressScanRanges;
import app.byteland.ghidra.adapter.ghidra.scan.BoundedAddressScan;
import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.listing.DataUnitResource;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;

final class ListingDataQueries {
  private final GhidraSession context;

  ListingDataQueries(GhidraSession context) {
    this.context = context;
  }

  Page<DataUnitResource> listDataUnits(
      AddressScanOptions options, int limit, String direction, String cursorRaw) {
    int normalizedLimit = Page.clampLimit(limit);
    AddressScanRanges.Resolved range = AddressScanRanges.resolve(context, options, true);
    Address cursor = cursorRaw == null ? null : parseAddress(cursorRaw);
    boolean forward = !"backward".equalsIgnoreCase(direction);

    BoundedAddressScan<DataUnitResource> scan =
        BoundedAddressScan.start(
            normalizedLimit, options.timeoutMs(), range.startText(), range.endText());
    Data data = cursor == null ? firstData(range.start(), forward) : nextData(cursor, forward);
    while (data != null) {
      if (forward ? range.afterEnd(data.getAddress()) : !range.includes(data.getAddress())) break;
      String address = AddressUtil.canonicalAddress(data.getAddress());
      scan.visit(address, address, ListingDescriptions.toDataItem(data, context));
      if (scan.stopped()) break;
      data = nextData(data, forward);
    }

    return scan.finish();
  }

  private Address parseAddress(String rawAddress) {
    return context.parseAddress(rawAddress);
  }

  private Data firstData(Address start, boolean forward) {
    Data data = context.script().getDataAt(start);
    if (data != null) {
      return data;
    }
    return forward ? context.script().getDataAfter(start) : context.script().getDataBefore(start);
  }

  private Data nextData(Data data, boolean forward) {
    return forward ? context.script().getDataAfter(data) : context.script().getDataBefore(data);
  }

  private Data nextData(Address address, boolean forward) {
    return forward
        ? context.script().getDataAfter(address)
        : context.script().getDataBefore(address);
  }
}
