package app.byteland.ghidra.adapter.ghidra.listing;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.function.FunctionLookupQueries;
import app.byteland.ghidra.adapter.ghidra.scan.AddressScanRanges;
import app.byteland.ghidra.adapter.ghidra.scan.BoundedAddressScan;
import app.byteland.ghidra.service.AddressScanOptions;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.listing.InstructionResource;
import app.byteland.ghidra.service.listing.ListingService.InstructionListQuery;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import java.util.Locale;
import java.util.NoSuchElementException;

final class ListingInstructionQueries {
  private final GhidraSession context;
  private final FunctionLookupQueries functionLookup;

  ListingInstructionQueries(GhidraSession context) {
    this.context = context;
    this.functionLookup = new FunctionLookupQueries(context);
  }

  Page<InstructionResource> listInstructions(
      AddressScanOptions options, int limit, String direction, String cursorRaw) {
    return listInstructions(
        new InstructionListQuery(options, limit, direction, cursorRaw, null, null, null));
  }

  Page<InstructionResource> listInstructions(InstructionListQuery query) {
    int normalizedLimit = Page.clampLimit(query.limit());
    Address cursor =
        query.cursor() == null || query.cursor().isBlank() ? null : parseAddress(query.cursor());
    boolean forward = !"backward".equalsIgnoreCase(query.direction());
    String mnemonicFilter = normalizeToken(query.mnemonic());
    String flowTypeFilter = normalizeFlowType(query.flowType());
    Function owningFunction =
        query.function() == null || query.function().isBlank()
            ? null
            : functionLookup.resolveFlexible(query.function(), "/filter/function");

    if (owningFunction != null) {
      return listFunctionInstructions(
          owningFunction, query.scan(), normalizedLimit, forward, cursor, mnemonicFilter,
          flowTypeFilter);
    }

    AddressScanRanges.Resolved range = AddressScanRanges.resolve(context, query.scan(), true);
    BoundedAddressScan<InstructionResource> scan =
        BoundedAddressScan.start(
            normalizedLimit, query.scan().timeoutMs(), range.startText(), range.endText());
    Instruction instruction =
        cursor == null
            ? firstInstruction(range.start(), forward)
            : nextInstruction(cursor, forward);
    while (instruction != null) {
      if (forward
          ? range.afterEnd(instruction.getAddress())
          : !range.includes(instruction.getAddress())) break;
      String address = AddressUtil.canonicalAddress(instruction.getAddress());
      InstructionResource item =
          matchesInstruction(instruction, mnemonicFilter, flowTypeFilter)
              ? ListingDescriptions.toInstructionItem(instruction, context)
              : null;
      scan.visit(address, address, item);
      if (scan.stopped()) break;
      instruction = nextInstruction(instruction, forward);
    }

    return scan.finish();
  }

  private Page<InstructionResource> listFunctionInstructions(
      Function function,
      AddressScanOptions options,
      int normalizedLimit,
      boolean forward,
      Address cursor,
      String mnemonicFilter,
      String flowTypeFilter) {
    AddressSetView body = function.getBody();
    boolean explicitBounds = options.start() != null || options.end() != null;
    if (body.isEmpty() && !explicitBounds) {
      String entry = AddressUtil.canonicalAddress(function.getEntryPoint());
      return BoundedAddressScan.<InstructionResource>start(
              normalizedLimit, options.timeoutMs(), entry, entry)
          .finish();
    }
    AddressScanRanges.Resolved range =
        explicitBounds
            ? AddressScanRanges.resolve(context, options, true)
            : AddressScanRanges.of(body.getMinAddress(), body.getMaxAddress());
    BoundedAddressScan<InstructionResource> scan =
        BoundedAddressScan.start(
            normalizedLimit, options.timeoutMs(), range.startText(), range.endText());
    if (body.isEmpty()) {
      return scan.finish();
    }

    AddressSet searchSet = new AddressSet(body);
    if (explicitBounds) {
      if (!body.getMinAddress().getAddressSpace().equals(range.start().getAddressSpace())) {
        return scan.finish();
      }
      Address end =
          range.end() != null ? range.end() : range.start().getAddressSpace().getMaxAddress();
      searchSet = searchSet.intersectRange(range.start(), end);
    }
    if (cursor != null && !searchSet.isEmpty()) {
      searchSet = trimSetAtCursor(searchSet, cursor, forward);
    }

    InstructionIterator iterator =
        context.currentProgram().getListing().getInstructions(searchSet, forward);
    while (iterator.hasNext()) {
      Instruction instruction = iterator.next();
      String address = AddressUtil.canonicalAddress(instruction.getAddress());
      InstructionResource item =
          matchesInstruction(instruction, mnemonicFilter, flowTypeFilter)
              ? ListingDescriptions.toInstructionItem(instruction, context)
              : null;
      scan.visit(address, address, item);
      if (scan.stopped()) {
        break;
      }
    }
    return scan.finish();
  }

  private static AddressSet trimSetAtCursor(AddressSet set, Address cursor, boolean forward) {
    if (!set.getMinAddress().getAddressSpace().equals(cursor.getAddressSpace())) {
      return forward && set.getMinAddress().compareTo(cursor) <= 0
              || !forward && set.getMaxAddress().compareTo(cursor) >= 0
          ? new AddressSet()
          : set;
    }
    if (forward) {
      Address next = cursor.next();
      if (next == null || next.compareTo(set.getMaxAddress()) > 0) {
        return new AddressSet();
      }
      return next.compareTo(set.getMinAddress()) <= 0
          ? set
          : set.intersectRange(next, set.getMaxAddress());
    }
    Address previous = cursor.previous();
    if (previous == null || previous.compareTo(set.getMinAddress()) < 0) {
      return new AddressSet();
    }
    return previous.compareTo(set.getMaxAddress()) >= 0
        ? set
        : set.intersectRange(set.getMinAddress(), previous);
  }

  private static boolean matchesInstruction(
      Instruction instruction, String mnemonicFilter, String flowTypeFilter) {
    if (mnemonicFilter != null
        && !instruction.getMnemonicString().toLowerCase(Locale.ROOT).equals(mnemonicFilter)) {
      return false;
    }
    if (flowTypeFilter != null) {
      String actualFlow = normalizeFlowType(instruction.getFlowType().getName());
      return flowTypeFilter.equals(actualFlow);
    }
    return true;
  }

  private static String normalizeToken(String raw) {
    return raw == null || raw.isBlank() ? null : raw.trim().toLowerCase(Locale.ROOT);
  }

  private static String normalizeFlowType(String raw) {
    return raw == null || raw.isBlank()
        ? null
        : raw.trim().replace('-', '_').toLowerCase(Locale.ROOT);
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
