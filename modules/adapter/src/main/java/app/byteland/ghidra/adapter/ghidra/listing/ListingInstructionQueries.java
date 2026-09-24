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

    BoundedAddressScan<InstructionResource> scan =
        BoundedAddressScan.start(
            normalizedLimit, options.timeoutMs(), range.startText(), range.endText());
    Instruction instruction =
        cursor == null
            ? firstInstruction(range.start(), forward)
            : nextInstruction(cursor, forward);
    while (instruction != null) {
      if (forward
          ? range.afterEnd(instruction.getAddress())
          : !range.includes(instruction.getAddress())) break;
      String address = AddressUtil.canonicalAddress(instruction.getAddress());
      scan.visit(address, address, ListingDescriptions.toInstructionItem(instruction, context));
      if (scan.stopped()) break;
      instruction = nextInstruction(instruction, forward);
    }

    return scan.finish();
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

  private Instruction firstInstruction(Address start, boolean forward) {
    Instruction instruction = context.script().getInstructionAt(start);
    if (instruction != null) {
      return instruction;
    }
    return forward
        ? context.script().getInstructionAfter(start)
        : context.script().getInstructionBefore(start);
  }

  private Instruction nextInstruction(Instruction instruction, boolean forward) {
    return forward
        ? context.script().getInstructionAfter(instruction)
        : context.script().getInstructionBefore(instruction);
  }

  private Instruction nextInstruction(Address address, boolean forward) {
    return forward
        ? context.script().getInstructionAfter(address)
        : context.script().getInstructionBefore(address);
  }
}
