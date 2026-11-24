package app.byteland.ghidra.adapter.ghidra.listing;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.scan.AddressScanRanges;
import app.byteland.ghidra.adapter.ghidra.scan.BoundedAddressScan;
import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.listing.InstructionResource;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import java.util.NoSuchElementException;

final class ListingInstructionQueries {
  private final GhidraSession context;

  ListingInstructionQueries(GhidraSession context) {
    this.context = context;
  }

  Page<InstructionResource> listInstructions(
      AddressScanOptions options, int limit, String direction, String cursorRaw) {
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

  InstructionResource getInstruction(String rawAddress) {
    Address address = parseAddress(rawAddress);
    Instruction instruction = context.currentProgram().getListing().getInstructionAt(address);
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
