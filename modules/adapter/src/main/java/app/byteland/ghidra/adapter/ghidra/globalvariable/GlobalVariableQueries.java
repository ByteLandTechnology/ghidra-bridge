package app.byteland.ghidra.adapter.ghidra.globalvariable;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.FieldProjections;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.scan.AddressScanRanges;
import app.byteland.ghidra.adapter.ghidra.scan.BoundedAddressScan;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.globalvariable.GlobalVariableResource;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService.Query;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import java.util.Locale;
import java.util.NoSuchElementException;
import java.util.Set;

final class GlobalVariableQueries {
  private final GhidraSession context;

  GlobalVariableQueries(GhidraSession context) {
    this.context = context;
  }

  GlobalVariableResource getGlobalVariable(String rawAddress) {
    return getGlobalVariable(rawAddress, null);
  }

  GlobalVariableResource getGlobalVariable(String rawAddress, Set<String> fields) {
    Address address = context.parseAddress(rawAddress);
    Data data = context.currentProgram().getListing().getDefinedDataAt(address);
    if (data == null) throw new NoSuchElementException("global variable not found: " + rawAddress);
    return describe(data, fields);
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
    Set<String> fields = query.fields();
    boolean filterNeedsSymbol = query.namespace() != null || query.name() != null;
    boolean fieldsNeedSymbol = symbolNeededForFields(fields);
    while (iterator.hasNext()) {
      Data data = iterator.next();
      if (cursor != null && data.getAddress().compareTo(cursor) <= 0) continue;
      if (range.afterEnd(data.getAddress())) break;
      Symbol primary =
          filterNeedsSymbol || fieldsNeedSymbol
              ? context.currentProgram().getSymbolTable().getPrimarySymbol(data.getAddress())
              : null;
      GlobalVariableResource match =
          !filterNeedsSymbol || matches(primary, query)
              ? GlobalVariableDescriptions.describe(data, primary, fields)
              : null;
      String address = AddressUtil.canonicalAddress(data.getAddress());
      scan.visit(address, address, match);
      if (scan.stopped()) break;
    }
    return scan.finish();
  }

  private GlobalVariableResource describe(Data data, Set<String> fields) {
    Symbol primary =
        symbolNeededForFields(fields)
            ? context.currentProgram().getSymbolTable().getPrimarySymbol(data.getAddress())
            : null;
    return GlobalVariableDescriptions.describe(data, primary, fields);
  }

  private static boolean symbolNeededForFields(Set<String> fields) {
    return FieldProjections.allows(fields, "name")
        || FieldProjections.allows(fields, "namespace")
        || FieldProjections.allows(fields, "source_type");
  }

  private static boolean matches(Symbol primarySymbol, Query query) {
    Namespace parent = primarySymbol == null ? null : primarySymbol.getParentNamespace();
    String namespaceName = parent == null ? null : parent.getName();
    if (query.namespace() != null && !query.namespace().equals(namespaceName)) return false;
    if (query.name() == null) return true;
    String symbolName = primarySymbol == null ? null : primarySymbol.getName();
    if (symbolName == null) return false;
    String requested = query.name();
    String actual = symbolName;
    if (!query.caseSensitive()) {
      requested = requested.toLowerCase(Locale.ROOT);
      actual = actual.toLowerCase(Locale.ROOT);
    }
    return actual.contains(requested);
  }
}
