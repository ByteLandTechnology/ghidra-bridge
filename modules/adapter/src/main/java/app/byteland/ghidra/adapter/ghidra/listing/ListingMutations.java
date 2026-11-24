package app.byteland.ghidra.adapter.ghidra.listing;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.TransactionExecutionException;
import app.byteland.ghidra.service.listing.ClearedCodeUnitsResource;
import app.byteland.ghidra.service.listing.InstructionResource;
import app.byteland.ghidra.service.listing.ListingScope;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.AssemblyBuffer;
import ghidra.app.plugin.assembler.AssemblyError;
import ghidra.app.plugin.assembler.AssemblyException;
import ghidra.app.plugin.assembler.AssemblySyntaxException;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.disassemble.DisassemblerMessageListener;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.TaskMonitor;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class ListingMutations {
  private static final Pattern SLEIGH_TOKEN =
      Pattern.compile("(0[xXbB][0-9a-fA-F]+)|([A-Za-z_][A-Za-z0-9_.]*)");
  private final GhidraSession context;

  ListingMutations(GhidraSession context) {
    this.context = context;
  }

  List<InstructionResource> assembleInstructions(
      String rawAddress, List<String> rawInstructions, boolean padNop) {
    List<String> lines = normalizeMnemonicLines(rawInstructions);
    Program program = context.currentProgram();
    Memory memory = program.getMemory();
    Listing listing = program.getListing();
    Address start = context.parseAddress(rawAddress);
    requireInitializedRange(memory, start, start);

    Assembler assembler = ListingAssemblerCache.assemblerFor(program);
    AssemblyBuffer buffer = new AssemblyBuffer(assembler, start);
    List<Address> instructionStarts = new ArrayList<>();
    for (String line : lines) {
      Address lineStart = buffer.getNext();
      instructionStarts.add(lineStart);
      try {
        byte[] encoded = assembleLine(buffer, line);
        if (encoded == null || encoded.length == 0) {
          throw new IllegalArgumentException(
              "instruction produced zero bytes at "
                  + AddressUtil.canonicalAddress(lineStart)
                  + ": "
                  + line);
        }
      } catch (AssemblyException | AssemblyError | UnsupportedOperationException | IOException ex) {
        throw new IllegalArgumentException(
            "unable to assemble '"
                + line
                + "' at "
                + AddressUtil.canonicalAddress(lineStart)
                + ": "
                + ex.getMessage(),
            ex);
      }
    }

    byte[] bytes = buffer.getBytes();
    if (bytes.length == 0) {
      throw new IllegalArgumentException("assembled instructions produced zero bytes");
    }
    Address end = addLengthMinusOne(start, bytes.length);
    requireInitializedRange(memory, start, end);

    CodeUnit tailUnit = listing.getCodeUnitContaining(end);
    if (padNop
        && tailUnit instanceof Instruction
        && tailUnit.getMaxAddress().compareTo(end) > 0) {
      Address targetEnd = tailUnit.getMaxAddress();
      requireInitializedRange(memory, start, targetEnd);
      while (buffer.getNext().compareTo(targetEnd) <= 0) {
        Address nopAddr = buffer.getNext();
        byte[] nopBytes = assembleNop(assembler, nopAddr);
        Address nopEnd = addLengthMinusOne(nopAddr, nopBytes.length);
        if (nopEnd.compareTo(targetEnd) > 0) {
          throw new IllegalArgumentException(
              "leftover instruction bytes through "
                  + AddressUtil.canonicalAddress(targetEnd)
                  + " cannot be padded evenly with NOP");
        }
        instructionStarts.add(nopAddr);
        try {
          buffer.emit(nopBytes);
        } catch (IOException ex) {
          throw new IllegalStateException("unable to emit NOP bytes", ex);
        }
      }
      bytes = buffer.getBytes();
      end = addLengthMinusOne(start, bytes.length);
      requireInitializedRange(memory, start, end);
      tailUnit = listing.getCodeUnitContaining(end);
    }

    Address clearEnd =
        tailUnit != null
                && isDefinedCodeUnit(tailUnit)
                && tailUnit.getMaxAddress().compareTo(end) > 0
            ? tailUnit.getMaxAddress()
            : end;
    listing.clearCodeUnits(start, clearEnd, false);

    try {
      assembler.patchProgram(bytes, start);
    } catch (MemoryAccessException ex) {
      throw new TransactionExecutionException(
          "unable to write assembled bytes: " + ex.getMessage(), ex);
    }

    AddressSet assembledRange = new AddressSet(start, end);
    Disassembler disassembler =
        Disassembler.getDisassembler(
            program, TaskMonitor.DUMMY, DisassemblerMessageListener.IGNORE);
    for (Address seed : instructionStarts) {
      if (listing.getInstructionContaining(seed) == null) {
        disassembler.disassemble(seed, assembledRange, false);
      }
    }

    return collectInstructions(listing, assembledRange);
  }

  List<InstructionResource> disassemble(ListingScope scope, Boolean followFlowOption) {
    Program program = context.currentProgram();
    Memory memory = program.getMemory();
    Listing listing = program.getListing();
    return switch (scope) {
      case ListingScope.AddressScope addressScope -> {
        Address start = context.parseAddress(addressScope.address());
        requireInitializedRange(memory, start, start);
        CodeUnit existing = listing.getCodeUnitContaining(start);
        if (existing instanceof Data data && data.isDefined()) {
          throw new IllegalArgumentException(
              "cannot disassemble defined data at "
                  + AddressUtil.canonicalAddress(start)
                  + "; clear code units first");
        }
        if (existing instanceof Instruction instruction
            && !instruction.getAddress().equals(start)) {
          throw new IllegalArgumentException(
              "address "
                  + AddressUtil.canonicalAddress(start)
                  + " is inside an existing instruction starting at "
                  + AddressUtil.canonicalAddress(instruction.getAddress()));
        }
        boolean followFlow = followFlowOption == null || followFlowOption;
        DisassembleCommand command = new DisassembleCommand(start, null, followFlow);
        command.enableCodeAnalysis(false);
        context.runCommand(command, "unable to disassemble");
        AddressSet decoded = new AddressSet(command.getDisassembledAddressSet());
        decoded.add(start, start);
        yield collectInstructions(listing, decoded);
      }
      case ListingScope.RangeScope rangeScope -> {
        AddressRangeBounds bounds = parseRange(rangeScope.start(), rangeScope.end());
        requireInitializedRange(memory, bounds.start(), bounds.end());
        AddressSet rangeSet = new AddressSet(bounds.start(), bounds.end());
        boolean followFlow = followFlowOption == null || followFlowOption;
        DisassembleCommand command = new DisassembleCommand(rangeSet, rangeSet, followFlow);
        command.enableCodeAnalysis(false);
        context.runCommand(command, "unable to disassemble");
        AddressSet decoded = new AddressSet(command.getDisassembledAddressSet());
        decoded.add(rangeSet);
        yield collectInstructions(listing, decoded.intersect(rangeSet));
      }
    };
  }

  ClearedCodeUnitsResource clearCodeUnits(ListingScope scope, boolean clearContext) {
    Program program = context.currentProgram();
    Memory memory = program.getMemory();
    Listing listing = program.getListing();
    AddressRangeBounds bounds =
        switch (scope) {
          case ListingScope.AddressScope addressScope -> {
            Address addr = context.parseAddress(addressScope.address());
            yield new AddressRangeBounds(addr, addr);
          }
          case ListingScope.RangeScope rangeScope ->
              parseRange(rangeScope.start(), rangeScope.end());
        };
    requireMappedRange(memory, bounds.start(), bounds.end());

    CodeUnit firstUnit = listing.getCodeUnitContaining(bounds.start());
    Address effectiveStart =
        firstUnit != null && firstUnit.getMinAddress().compareTo(bounds.start()) < 0
            ? firstUnit.getMinAddress()
            : bounds.start();
    CodeUnit lastUnit = listing.getCodeUnitContaining(bounds.end());
    Address effectiveEnd =
        lastUnit != null && lastUnit.getMaxAddress().compareTo(bounds.end()) > 0
            ? lastUnit.getMaxAddress()
            : bounds.end();

    listing.clearCodeUnits(bounds.start(), bounds.end(), clearContext);
    long length = effectiveEnd.subtract(effectiveStart) + 1L;
    return new ClearedCodeUnitsResource(
        AddressUtil.canonicalAddress(effectiveStart),
        AddressUtil.canonicalAddress(effectiveEnd),
        length);
  }

  static Address addLengthMinusOne(Address start, int byteLength) {
    if (byteLength <= 0) {
      throw new IllegalArgumentException("byte length must be positive");
    }
    try {
      return start.addNoWrap(byteLength - 1L);
    } catch (AddressOverflowException ex) {
      throw new IllegalArgumentException(
          "byte range starting at "
              + AddressUtil.canonicalAddress(start)
              + " overflows address space",
          ex);
    }
  }

  static void requireInitializedRange(Memory memory, Address start, Address end) {
    if (!isAllInitializedBlocks(memory, start, end)) {
      throw new IllegalArgumentException(
          "address range "
              + AddressUtil.canonicalAddress(start)
              + ".."
              + AddressUtil.canonicalAddress(end)
              + " is not in initialized memory");
    }
  }

  static boolean isAllInitializedBlocks(Memory memory, Address start, Address end) {
    Address current = start;
    while (true) {
      MemoryBlock block = memory.getBlock(current);
      if (block == null || !block.isInitialized()) {
        return false;
      }
      if (block.getEnd().compareTo(end) >= 0) {
        return true;
      }
      Address next = block.getEnd().next();
      if (next == null || !next.getAddressSpace().equals(end.getAddressSpace())) {
        return false;
      }
      current = next;
    }
  }

  static void requireMappedRange(Memory memory, Address start, Address end) {
    if (!memory.contains(start, end)) {
      throw new IllegalArgumentException(
          "address range "
              + AddressUtil.canonicalAddress(start)
              + ".."
              + AddressUtil.canonicalAddress(end)
              + " is not mapped in program memory");
    }
  }

  static boolean isDefinedCodeUnit(CodeUnit unit) {
    if (unit instanceof Instruction) {
      return true;
    }
    if (unit instanceof Data data) {
      return data.isDefined();
    }
    return false;
  }

  private AddressRangeBounds parseRange(String startRaw, String endRaw) {
    Address start = context.parseAddress(startRaw);
    Address end = context.parseAddress(endRaw);
    if (!start.getAddressSpace().equals(end.getAddressSpace())) {
      throw new IllegalArgumentException("start and end must be in the same address space");
    }
    if (start.compareTo(end) > 0) {
      throw new IllegalArgumentException("start must not be greater than end");
    }
    return new AddressRangeBounds(start, end);
  }

  private static List<String> normalizeMnemonicLines(List<String> rawInstructions) {
    if (rawInstructions == null || rawInstructions.isEmpty()) {
      throw new IllegalArgumentException("instructions must not be empty");
    }
    List<String> lines = new ArrayList<>();
    for (String entry : rawInstructions) {
      if (entry == null) {
        continue;
      }
      for (String part : entry.split("\\R")) {
        String trimmed = part.trim();
        if (!trimmed.isEmpty()) {
          lines.add(trimmed);
        }
      }
    }
    if (lines.isEmpty()) {
      throw new IllegalArgumentException("instructions must contain at least one mnemonic");
    }
    return List.copyOf(lines);
  }

  private static byte[] assembleLine(AssemblyBuffer buffer, String line)
      throws AssemblyException, IOException {
    try {
      return buffer.assemble(line);
    } catch (AssemblySyntaxException original) {
      for (boolean upper : List.of(true, false)) {
        String candidate = recaseTokens(line, upper);
        if (candidate.equals(line)) {
          continue;
        }
        try {
          return buffer.assemble(candidate);
        } catch (AssemblyException ignored) {
          // Keep original syntax exception if fallback candidates also fail.
        }
      }
      throw original;
    }
  }

  private static String recaseTokens(String line, boolean upper) {
    Matcher matcher = SLEIGH_TOKEN.matcher(line);
    StringBuilder out = new StringBuilder(line.length());
    while (matcher.find()) {
      String numeric = matcher.group(1);
      String word = matcher.group(2);
      String replacement;
      if (numeric != null) {
        replacement =
            "0" + Character.toLowerCase(numeric.charAt(1)) + numeric.substring(2);
      } else {
        replacement =
            upper ? word.toUpperCase(Locale.ROOT) : word.toLowerCase(Locale.ROOT);
      }
      matcher.appendReplacement(out, Matcher.quoteReplacement(replacement));
    }
    matcher.appendTail(out);
    return out.toString();
  }

  private static byte[] assembleNop(Assembler assembler, Address address) {
    for (String candidate : List.of("nop", "NOP")) {
      try {
        byte[] bytes = assembler.assembleLine(address, candidate);
        if (bytes != null && bytes.length > 0) {
          return bytes;
        }
      } catch (AssemblyException | AssemblyError | UnsupportedOperationException ignored) {
        // Try next candidate mnemonic.
      }
    }
    throw new IllegalArgumentException(
        "unable to assemble NOP padding at " + AddressUtil.canonicalAddress(address));
  }

  private List<InstructionResource> collectInstructions(Listing listing, AddressSet addresses) {
    List<InstructionResource> items = new ArrayList<>();
    InstructionIterator iterator = listing.getInstructions(addresses, true);
    while (iterator.hasNext()) {
      items.add(ListingDescriptions.toInstructionItem(iterator.next(), context));
    }
    return List.copyOf(items);
  }

  private record AddressRangeBounds(Address start, Address end) {}
}
