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
import java.util.NoSuchElementException;

final class ListingInstructionQueries {
  private final GhidraSession context;
  private final AddressScopeResolver scopes;

  ListingInstructionQueries(GhidraSession context, AddressScopeResolver scopes) {
    this.context = context;
    this.scopes = scopes;
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
