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
import ghidra.program.model.listing.DataIterator;

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
    Address iterationStart = ListingInstructionQueries.iterationStart(range, cursor, forward);

    BoundedAddressScan<DataUnitResource> scan =
        BoundedAddressScan.start(
            normalizedLimit, options.timeoutMs(), range.startText(), range.endText());
    if (ListingInstructionQueries.outOfRange(iterationStart, range, forward)) {
      return scan.finish();
    }
    DataIterator dataUnits =
        context.currentProgram().getListing().getDefinedData(iterationStart, forward);
    while (dataUnits.hasNext()) {
      Data data = dataUnits.next();
      Address address = data.getAddress();
      if (ListingInstructionQueries.atOrBeforeCursor(address, cursor, forward)) continue;
      if (ListingInstructionQueries.outOfRange(address, range, forward)) break;
      String canonical = AddressUtil.canonicalAddress(address);
      scan.visit(canonical, canonical, ListingDescriptions.toDataItem(data, context));
      if (scan.stopped()) break;
    }

    return scan.finish();
  }

  private Address parseAddress(String rawAddress) {
    return context.parseAddress(rawAddress);
  }
}
