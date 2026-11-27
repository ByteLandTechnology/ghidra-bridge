package app.byteland.ghidra.adapter.ghidra.listing;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.TransactionExecutionException;
import app.byteland.ghidra.service.listing.AddressOrRangeScope;
import app.byteland.ghidra.service.listing.InstructionResource;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.AssemblyError;
import ghidra.app.plugin.assembler.AssemblySemanticException;
import ghidra.app.plugin.assembler.AssemblySyntaxException;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.disassemble.DisassemblerMessageListener;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.task.TaskMonitor;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;

final class ListingInstructionMutations {
  private static final List<String> NOP_CANDIDATES = List.of("NOP", "nop");

  private final GhidraSession context;
  private final ListingAssemblerCache assemblerCache;

  ListingInstructionMutations(GhidraSession context, ListingAssemblerCache assemblerCache) {
    this.context = context;
    this.assemblerCache = assemblerCache;
  }

  List<InstructionResource> assembleInstructions(
      String rawAddress, List<String> rawInstructions, boolean padNop) {
    Address start = context.parseAddress(rawAddress);
    List<String> lines = normalizeLines(rawInstructions);
    Program program = context.currentProgram();
    Assembler assembler = assemblerCache.get(program);
    AssemblyPatternBlock contextBlock = assembler.getContextAt(start).fillMask();

    ByteArrayOutputStream encoded = new ByteArrayOutputStream();
    List<Address> instructionStarts = new ArrayList<>();
    Address cursor = start;
    for (int index = 0; index < lines.size(); index++) {
      byte[] lineBytes = assembleLine(assembler, cursor, lines.get(index), contextBlock);
      instructionStarts.add(cursor);
      encoded.writeBytes(lineBytes);
      if (index + 1 < lines.size()) {
        cursor = advanceAddress(cursor, lineBytes.length, "assembled instructions");
      }
    }

    byte[] assembledBytes = encoded.toByteArray();
    Address assembledEnd =
        advanceAddress(start, assembledBytes.length - 1L, "assembled instructions");
    Listing listing = program.getListing();
    Address clearStart = ListingCodeUnitMutations.expandClearStart(listing, start);
    Address clearEnd = ListingCodeUnitMutations.expandClearEnd(listing, assembledEnd);

    Instruction overwrittenEnd = listing.getInstructionContaining(assembledEnd);
    Address leftoverEnd =
        overwrittenEnd != null && overwrittenEnd.getMaxAddress().compareTo(assembledEnd) > 0
            ? overwrittenEnd.getMaxAddress()
            : null;

    Address finalEnd = assembledEnd;
    if (padNop && leftoverEnd != null) {
      appendNopPadding(
          assembler, contextBlock, assembledEnd, leftoverEnd, encoded, instructionStarts);
      finalEnd = leftoverEnd;
    }

    byte[] finalBytes = encoded.toByteArray();
    AddressSet writtenRange = new AddressSet(start, finalEnd);
    requireInitializedMemory(program, writtenRange, "target range must be in initialized memory");

    listing.clearCodeUnits(clearStart, clearEnd, false);
    patchAndDecodeAll(program, assembler, start, finalBytes, writtenRange, instructionStarts);
    return collectInstructions(listing, writtenRange, "assembler decoded zero instructions");
  }

  List<InstructionResource> disassembleInstructions(AddressOrRangeScope scope, boolean followFlow) {
    return switch (scope) {
      case AddressOrRangeScope.AddressScope address ->
          disassembleAtAddress(context.parseAddress(address.address()), followFlow);
      case AddressOrRangeScope.RangeScope range ->
          disassembleRange(
              context.parseAddress(range.start()), context.parseAddress(range.end()), followFlow);
    };
  }

  private List<InstructionResource> disassembleAtAddress(Address start, boolean followFlow) {
    Program program = context.currentProgram();
    requireInitializedMemory(
        program, new AddressSet(start, start), "address must be in initialized memory");
    int alignment = program.getLanguage().getInstructionAlignment();
    if (alignment > 1 && Long.remainderUnsigned(start.getOffset(), alignment) != 0) {
      throw new IllegalArgumentException("address must align to " + alignment + " bytes");
    }

    Listing listing = program.getListing();
    CodeUnit current = listing.getCodeUnitContaining(start);
    if (current instanceof Instruction && current.getMinAddress().compareTo(start) < 0) {
      throw new IllegalArgumentException(
          "address is inside an instruction at "
              + AddressUtil.canonicalAddress(current.getMinAddress()));
    }
    if (current instanceof Data data && data.isDefined()) {
      throw new IllegalArgumentException(
          "address has defined data; clear code units before disassembly");
    }

    AddressSet restricted = followFlow ? null : new AddressSet(start, start);
    DisassembleCommand command = new DisassembleCommand(start, restricted, followFlow);
    command.enableCodeAnalysis(false);
    context.runCommand(command, "unable to disassemble instructions");

    AddressSet decoded = new AddressSet(command.getDisassembledAddressSet());
    Instruction first = listing.getInstructionAt(start);
    if (first != null) {
      decoded.add(first.getMinAddress(), first.getMaxAddress());
    }
    if (decoded.isEmpty()) {
      throw new TransactionExecutionException(
          "unable to disassemble instruction at " + AddressUtil.canonicalAddress(start));
    }
    return collectInstructions(listing, decoded, "unable to disassemble instruction");
  }

  private List<InstructionResource> disassembleRange(
      Address start, Address end, boolean followFlow) {
    ListingCodeUnitMutations.validateRange(start, end);
    Program program = context.currentProgram();
    AddressSet range = new AddressSet(start, end);
    requireInitializedMemory(program, range, "range must be in initialized memory");

    DisassembleCommand command = new DisassembleCommand(range, range, followFlow);
    command.enableCodeAnalysis(false);
    context.runCommand(command, "unable to disassemble instructions");
    return collectInstructions(
        program.getListing(), range, "unable to disassemble instructions in range");
  }

  private List<InstructionResource> collectInstructions(
      Listing listing, AddressSet addresses, String emptyMessage) {
    List<InstructionResource> items = new ArrayList<>();
    for (Instruction instruction : listing.getInstructions(addresses, true)) {
      items.add(ListingDescriptions.toInstructionItem(instruction, context));
    }
    if (items.isEmpty()) {
      throw new TransactionExecutionException(emptyMessage);
    }
    return List.copyOf(items);
  }

  private static void patchAndDecodeAll(
      Program program,
      Assembler assembler,
      Address start,
      byte[] finalBytes,
      AddressSet writtenRange,
      List<Address> instructionStarts) {
    try {
      assembler.patchProgram(finalBytes, start);
    } catch (MemoryAccessException exception) {
      throw new TransactionExecutionException(
          "unable to write assembled bytes: " + exception.getMessage(), exception);
    }
    Listing listing = program.getListing();
    Disassembler disassembler = null;
    for (Address instStart : instructionStarts) {
      if (listing.getInstructionAt(instStart) != null) {
        continue;
      }
      if (disassembler == null) {
        disassembler =
            Disassembler.getDisassembler(
                program, TaskMonitor.DUMMY, DisassemblerMessageListener.IGNORE);
      }
      disassembler.disassemble(instStart, writtenRange, true);
    }
  }

  private static void appendNopPadding(
      Assembler assembler,
      AssemblyPatternBlock contextBlock,
      Address assembledEnd,
      Address leftoverEnd,
      ByteArrayOutputStream encoded,
      List<Address> instructionStarts) {
    Address nopCursor = advanceAddress(assembledEnd, 1L, "NOP fill");
    while (true) {
      byte[] nopBytes = assembleNop(assembler, nopCursor, contextBlock);
      Address nopEnd = advanceAddress(nopCursor, nopBytes.length - 1L, "NOP fill");
      int comparison = nopEnd.compareTo(leftoverEnd);
      if (comparison > 0) {
        throw new IllegalArgumentException(
            "NOP instruction length ("
                + nopBytes.length
                + ") does not fit leftover space up to "
                + AddressUtil.canonicalAddress(leftoverEnd));
      }
      instructionStarts.add(nopCursor);
      encoded.writeBytes(nopBytes);
      if (comparison == 0) {
        return;
      }
      nopCursor = advanceAddress(nopEnd, 1L, "NOP fill");
    }
  }

  private static byte[] assembleNop(
      Assembler assembler, Address at, AssemblyPatternBlock contextBlock) {
    IllegalArgumentException lastFailure = null;
    for (String mnemonic : NOP_CANDIDATES) {
      try {
        return assembleLine(assembler, at, mnemonic, contextBlock);
      } catch (IllegalArgumentException exception) {
        lastFailure = exception;
      }
    }
    throw new IllegalArgumentException(
        "program language does not define a standard NOP instruction", lastFailure);
  }

  private static byte[] assembleLine(
      Assembler assembler, Address at, String line, AssemblyPatternBlock contextBlock) {
    try {
      byte[] bytes = assembler.assembleLine(at, line, contextBlock);
      if (bytes == null || bytes.length == 0) {
        throw new IllegalArgumentException("assembler produced zero bytes for: " + line);
      }
      return bytes;
    } catch (AssemblySyntaxException | AssemblySemanticException | AssemblyError exception) {
      throw new IllegalArgumentException(
          "invalid assembly at "
              + AddressUtil.canonicalAddress(at)
              + " ("
              + line
              + "): "
              + exception.getMessage(),
          exception);
    }
  }

  private static List<String> normalizeLines(List<String> rawInstructions) {
    List<String> lines = new ArrayList<>();
    for (String entry : rawInstructions) {
      if (entry == null) {
        continue;
      }
      for (String part : entry.split("\\r?\\n")) {
        String trimmed = part.trim();
        if (!trimmed.isEmpty()) {
          lines.add(trimmed);
        }
      }
    }
    if (lines.isEmpty()) {
      throw new IllegalArgumentException("instructions must contain at least one statement");
    }
    return List.copyOf(lines);
  }

  private static Address advanceAddress(Address base, long offset, String label) {
    if (offset == 0L) {
      return base;
    }
    try {
      return base.addNoWrap(offset);
    } catch (AddressOverflowException exception) {
      throw new IllegalArgumentException(
          label + " exceeds address space bounds at " + AddressUtil.canonicalAddress(base),
          exception);
    }
  }

  private static void requireInitializedMemory(
      Program program, AddressSet addresses, String message) {
    if (!program.getMemory().getLoadedAndInitializedAddressSet().contains(addresses)) {
      throw new IllegalArgumentException(message);
    }
  }
}
