package app.byteland.ghidra.adapter.ghidra.listing;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.scan.AddressScanRanges;
import app.byteland.ghidra.adapter.ghidra.scan.BoundedAddressScan;
import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.listing.DataUnitResource;
import app.byteland.ghidra.service.listing.ListingService.DataUnitListQuery;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.Data;
import java.util.Locale;

final class ListingDataQueries {
  private final GhidraSession context;

  ListingDataQueries(GhidraSession context) {
    this.context = context;
  }

  Page<DataUnitResource> listDataUnits(
      AddressScanOptions options, int limit, String direction, String cursorRaw) {
    return listDataUnits(
        new DataUnitListQuery(options, limit, direction, cursorRaw, null, false, null, false));
  }

  Page<DataUnitResource> listDataUnits(DataUnitListQuery query) {
    int normalizedLimit = Page.clampLimit(query.limit());
    AddressScanRanges.Resolved range = AddressScanRanges.resolve(context, query.scan(), true);
    Address cursor =
        query.cursor() == null || query.cursor().isBlank() ? null : parseAddress(query.cursor());
    boolean forward = !"backward".equalsIgnoreCase(query.direction());
    String typeFilter =
        query.dataType() == null || query.dataType().isBlank()
            ? null
            : query.dataType().trim().toLowerCase(Locale.ROOT);
    String substringFilter =
        query.valueContains() == null || query.valueContains().isEmpty()
            ? null
            : (query.caseSensitive()
                ? query.valueContains()
                : query.valueContains().toLowerCase(Locale.ROOT));

    BoundedAddressScan<DataUnitResource> scan =
        BoundedAddressScan.start(
            normalizedLimit, query.scan().timeoutMs(), range.startText(), range.endText());
    Data data = cursor == null ? firstData(range.start(), forward) : nextData(cursor, forward);
    while (data != null) {
      if (forward ? range.afterEnd(data.getAddress()) : !range.includes(data.getAddress())) break;
      String address = AddressUtil.canonicalAddress(data.getAddress());
      DataUnitResource item =
          matchesDataFilters(
                  data, typeFilter, query.stringOnly(), substringFilter, query.caseSensitive())
              ? ListingDescriptions.toDataItem(data, context)
              : null;
      scan.visit(address, address, item);
      if (scan.stopped()) break;
      data = nextData(data, forward);
    }

    return scan.finish();
  }

  private static boolean matchesDataFilters(
      Data data,
      String lowerTypeFilter,
      boolean stringOnly,
      String substringFilter,
      boolean caseSensitive) {
    boolean isString = isStringData(data);
    if (stringOnly && !isString) {
      return false;
    }
    if (lowerTypeFilter != null && !matchesDataType(data.getDataType(), lowerTypeFilter)) {
      return false;
    }
    if (substringFilter != null
        && !matchesValueSubstring(data, isString, substringFilter, caseSensitive)) {
      return false;
    }
    return true;
  }

  private static boolean isStringData(Data data) {
    return data.hasStringValue() || StringDataInstance.isString(data);
  }

  private static boolean matchesDataType(DataType dataType, String lowerFilter) {
    if (dataType == null) {
      return false;
    }
    String name = dataType.getName();
    if (name != null && name.toLowerCase(Locale.ROOT).equals(lowerFilter)) {
      return true;
    }
    String display = dataType.getDisplayName();
    if (display != null && display.toLowerCase(Locale.ROOT).equals(lowerFilter)) {
      return true;
    }
    String path = dataType.getPathName();
    if (path != null) {
      String lowerPath = path.toLowerCase(Locale.ROOT);
      String normalizedFilter = lowerFilter.startsWith("/") ? lowerFilter : "/" + lowerFilter;
      return lowerPath.equals(lowerFilter) || lowerPath.equals(normalizedFilter);
    }
    return false;
  }

  private static boolean matchesValueSubstring(
      Data data, boolean isString, String needle, boolean caseSensitive) {
    if (isString) {
      String stringValue = StringDataInstance.getStringDataInstance(data).getStringValue();
      if (stringValue != null && containsText(stringValue, needle, caseSensitive)) {
        return true;
      }
    }
    Object rawValue = data.getValue();
    if (rawValue != null && containsText(String.valueOf(rawValue), needle, caseSensitive)) {
      return true;
    }
    String representation = data.getDefaultValueRepresentation();
    return representation != null && containsText(representation, needle, caseSensitive);
  }

  private static boolean containsText(String haystack, String needle, boolean caseSensitive) {
    return caseSensitive
        ? haystack.contains(needle)
        : haystack.toLowerCase(Locale.ROOT).contains(needle);
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
