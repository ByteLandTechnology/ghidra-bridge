package app.byteland.ghidra.adapter.ghidra.listing;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.scan.AddressScanRanges;
import app.byteland.ghidra.adapter.ghidra.scan.BoundedAddressScan;
import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.listing.FlowOverrideScope;
import app.byteland.ghidra.service.listing.FlowOverrideValue;
import app.byteland.ghidra.service.listing.InstructionResource;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

final class ListingFlowOverrideQueries {
  private final GhidraSession context;
  private final ListingFlowOverrideScopes scopes;

  ListingFlowOverrideQueries(GhidraSession context, ListingFlowOverrideScopes scopes) {
    this.context = context;
    this.scopes = scopes;
  }

  Page<InstructionResource> getFlowOverrides(
      FlowOverrideScope selected,
      List<FlowOverrideValue> flowOverrides,
      AddressScanOptions options,
      int limit,
      String cursorRaw) {
    ListingFlowOverrideScopes.ResolvedScope scope = scopes.resolve(selected);
    Address cursor = resolveCursor(cursorRaw, scope);
    AddressScanRanges.Resolved range =
        AddressScanRanges.of(scope.addresses().getMinAddress(), scope.addresses().getMaxAddress());
    Set<FlowOverrideValue> filters = new LinkedHashSet<>(flowOverrides);

    BoundedAddressScan<InstructionResource> scan =
        BoundedAddressScan.start(limit, options.timeoutMs(), range.startText(), range.endText());
    for (Instruction instruction :
        context.currentProgram().getListing().getInstructions(scope.addresses(), true)) {
      int comparedToCursor = instruction.getAddress().compareTo(cursor);
      if (comparedToCursor < 0 || (cursorRaw != null && comparedToCursor == 0)) continue;
      String address = AddressUtil.canonicalAddress(instruction.getAddress());
      InstructionResource match =
          filters.contains(valueOf(instruction))
              ? ListingDescriptions.toInstructionItem(instruction, null)
              : null;
      scan.visit(address, address, match);
      if (scan.stopped()) break;
    }
    return scan.finish();
  }

  private Address resolveCursor(String cursorRaw, ListingFlowOverrideScopes.ResolvedScope scope) {
    if (cursorRaw == null) {
      return scope.addresses().getMinAddress();
    }
    Address cursor = context.parseAddress(cursorRaw);
    if (!scope.addresses().contains(cursor)) {
      throw new IllegalArgumentException("cursor must be inside the selected scope");
    }
    return cursor;
  }

  private static FlowOverrideValue valueOf(Instruction instruction) {
    return FlowOverrideValue.valueOf(instruction.getFlowOverride().name());
  }
}
