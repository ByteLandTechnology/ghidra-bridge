package app.byteland.ghidra.adapter.ghidra.listing;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.scan.AddressScanRanges;
import app.byteland.ghidra.adapter.ghidra.scan.AddressScopeResolver;
import app.byteland.ghidra.adapter.ghidra.scan.BoundedAddressScan;
import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.listing.FlowOverrideScope;
import app.byteland.ghidra.service.listing.InstructionResource;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import java.util.NoSuchElementException;

final class ListingInstructionQueries {
  private final GhidraSession context;
  private final AddressScopeResolver scopes;

  ListingInstructionQueries(GhidraSession context) {
    this(context, new AddressScopeResolver(context));
  }

  ListingInstructionQueries(GhidraSession context, AddressScopeResolver scopes) {
    this.context = context;
    this.scopes = scopes;
  }

  Page<InstructionResource> listInstructions(
      AddressScanOptions options, int limit, String direction, String cursorRaw) {
    return listInstructions(null, options, limit, direction, cursorRaw);
  }

  Page<InstructionResource> listInstructions(
      FlowOverrideScope scope,
      AddressScanOptions options,
      int limit,
      String direction,
      String cursorRaw) {
    if (scope != null) {
      return listScopedInstructions(scope, options, limit, cursorRaw);
    }
    int normalizedLimit = Page.clampLimit(limit);
    AddressScanRanges.Resolved range = AddressScanRanges.resolve(context, options, true);
    Address cursor = cursorRaw == null ? null : parseAddress(cursorRaw);
    boolean forward = !"backward".equalsIgnoreCase(direction);
    Address iterationStart = iterationStart(range, cursor, forward);

    BoundedAddressScan<InstructionResource> scan =
        BoundedAddressScan.start(
            normalizedLimit, options.timeoutMs(), range.startText(), range.endText());
    if (outOfRange(iterationStart, range, forward)) {
      return scan.finish();
    }
    InstructionIterator instructions =
        context.currentProgram().getListing().getInstructions(iterationStart, forward);
    while (instructions.hasNext()) {
      Instruction instruction = instructions.next();
      Address address = instruction.getAddress();
      if (atOrBeforeCursor(address, cursor, forward)) continue;
      if (outOfRange(address, range, forward)) break;
      String canonical = AddressUtil.canonicalAddress(address);
      scan.visit(canonical, canonical, ListingDescriptions.toInstructionItem(instruction, context));
      if (scan.stopped()) break;
    }

    return scan.finish();
  }

  private Page<InstructionResource> listScopedInstructions(
      FlowOverrideScope selected, AddressScanOptions options, int limit, String cursorRaw) {
    int normalizedLimit = Page.clampLimit(limit);
    AddressSet scopedAddresses = new AddressSet(scopes.resolve(selected));
    if (options.start() != null || options.end() != null) {
      AddressScanRanges.Resolved clip = AddressScanRanges.resolve(context, options, true);
      scopedAddresses =
          scopedAddresses.intersect(
              new AddressSet(context.currentProgram(), clip.start(), clip.end()));
    }
    String requestedStart =
        scopedAddresses.isEmpty()
            ? options.start()
            : AddressUtil.canonicalAddress(scopedAddresses.getMinAddress());
    String requestedEnd =
        scopedAddresses.isEmpty()
            ? options.end()
            : AddressUtil.canonicalAddress(scopedAddresses.getMaxAddress());
    Address cursor = cursorRaw == null ? null : parseAddress(cursorRaw);
    AddressSet iterationSet =
        cursor == null ? scopedAddresses : tailFrom(scopedAddresses, cursor);

    BoundedAddressScan<InstructionResource> scan =
        BoundedAddressScan.start(
            normalizedLimit, options.timeoutMs(), requestedStart, requestedEnd);
    for (Instruction instruction :
        context.currentProgram().getListing().getInstructions(iterationSet, true)) {
      if (cursor != null && instruction.getAddress().compareTo(cursor) <= 0) {
        continue;
      }
      String address = AddressUtil.canonicalAddress(instruction.getAddress());
      scan.visit(address, address, ListingDescriptions.toInstructionItem(instruction, context));
      if (scan.stopped()) break;
    }
    return scan.finish();
  }

  private AddressSet tailFrom(AddressSet addresses, Address cursor) {
    if (addresses.isEmpty()) {
      return addresses;
    }
    Address max = addresses.getMaxAddress();
    if (cursor.compareTo(max) >= 0) {
      return new AddressSet();
    }
    return addresses.intersect(new AddressSet(context.currentProgram(), cursor, max));
  }

  InstructionResource getInstruction(String rawAddress) {
    Address address = parseAddress(rawAddress);
    Instruction instruction = context.script().getInstructionAt(address);
    if (instruction == null) {
      throw new NoSuchElementException("no instruction at address");
    }
    return ListingDescriptions.toInstructionItem(instruction, context);
  }

  private Address parseAddress(String rawAddress) {
    return context.parseAddress(rawAddress);
  }

  static Address iterationStart(AddressScanRanges.Resolved range, Address cursor, boolean forward) {
    if (forward) {
      return cursor != null && cursor.compareTo(range.start()) > 0 ? cursor : range.start();
    }
    return cursor != null && cursor.compareTo(range.end()) < 0 ? cursor : range.end();
  }

  static boolean atOrBeforeCursor(Address address, Address cursor, boolean forward) {
    if (cursor == null) return false;
    return forward ? address.compareTo(cursor) <= 0 : address.compareTo(cursor) >= 0;
  }

  static boolean outOfRange(Address address, AddressScanRanges.Resolved range, boolean forward) {
    return forward ? range.afterEnd(address) : address.compareTo(range.start()) < 0;
  }
}
