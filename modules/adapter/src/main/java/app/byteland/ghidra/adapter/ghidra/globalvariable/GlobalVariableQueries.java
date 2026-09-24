package app.byteland.ghidra.adapter.ghidra.globalvariable;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.scan.AddressScanRanges;
import app.byteland.ghidra.adapter.ghidra.scan.BoundedAddressScan;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.globalvariable.GlobalVariableResource;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService.Query;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.symbol.Symbol;
import java.util.Locale;
import java.util.NoSuchElementException;

final class GlobalVariableQueries {
  private final GhidraSession context;

  GlobalVariableQueries(GhidraSession context) {
    this.context = context;
  }

  GlobalVariableResource getGlobalVariable(String rawAddress) {
    Address address = context.parseAddress(rawAddress);
    Data data = context.currentProgram().getListing().getDefinedDataAt(address);
    if (data == null) throw new NoSuchElementException("global variable not found: " + rawAddress);
    return describe(data);
  }

  Page<GlobalVariableResource> listGlobalVariables(Query query) {
    AddressScanRanges.Resolved range = AddressScanRanges.resolve(context, query.scan(), true);
    Address cursor = query.cursor() == null ? null : context.parseAddress(query.cursor());
    Address iterationStart =
        cursor != null && cursor.compareTo(range.start()) > 0 ? cursor : range.start();
    DataIterator iterator =
        context.currentProgram().getListing().getDefinedData(iterationStart, true);
    BoundedAddressScan<GlobalVariableResource> scan =
        BoundedAddressScan.start(
            query.limit(), query.scan().timeoutMs(), range.startText(), range.endText());
    while (iterator.hasNext()) {
      Data data = iterator.next();
      if (cursor != null && data.getAddress().compareTo(cursor) <= 0) continue;
      if (range.afterEnd(data.getAddress())) break;
      GlobalVariableResource resource = describe(data);
      String address = AddressUtil.canonicalAddress(data.getAddress());
      scan.visit(address, address, matches(resource, query) ? resource : null);
      if (scan.stopped()) break;
    }
    return scan.finish();
  }

  private GlobalVariableResource describe(Data data) {
    Symbol primary = context.currentProgram().getSymbolTable().getPrimarySymbol(data.getAddress());
    return GlobalVariableDescriptions.describe(data, primary);
  }

  private static boolean matches(GlobalVariableResource resource, Query query) {
    if (query.namespace() != null && !query.namespace().equals(resource.namespace())) return false;
    if (query.name() == null) return true;
    if (resource.name() == null) return false;
    String requested = query.name();
    String actual = resource.name();
    if (!query.caseSensitive()) {
      requested = requested.toLowerCase(Locale.ROOT);
      actual = actual.toLowerCase(Locale.ROOT);
    }
    return actual.contains(requested);
  }
}
