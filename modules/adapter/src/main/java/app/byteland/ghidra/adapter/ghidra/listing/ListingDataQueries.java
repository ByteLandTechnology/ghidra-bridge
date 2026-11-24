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
      AddressScanOptions options, int limit, String cursorRaw) {
    int normalizedLimit = Page.clampLimit(limit);
    AddressScanRanges.Resolved range = AddressScanRanges.resolve(context, options, true);
    Address cursor = cursorRaw == null ? null : parseAddress(cursorRaw);

    BoundedAddressScan<DataUnitResource> scan =
        BoundedAddressScan.start(
            normalizedLimit, options.timeoutMs(), range.startText(), range.endText());
    Data data = cursor == null ? firstData(range.start()) : context.script().getDataAfter(cursor);
    while (data != null) {
      if (range.afterEnd(data.getAddress())) break;
      String address = AddressUtil.canonicalAddress(data.getAddress());
      scan.visit(address, address, ListingDescriptions.toDataItem(data, context));
      if (scan.stopped()) break;
      data = context.script().getDataAfter(data);
    }

    return scan.finish();
  }

  private Address parseAddress(String rawAddress) {
    return context.parseAddress(rawAddress);
  }

  private Data firstData(Address start) {
    Data data = context.script().getDataAt(start);
    if (data != null) {
      return data;
    }
    return context.script().getDataAfter(start);
  }
}
