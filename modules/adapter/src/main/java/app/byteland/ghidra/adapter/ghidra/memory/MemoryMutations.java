package app.byteland.ghidra.adapter.ghidra.memory;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.TransactionExecutionException;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;

final class MemoryMutations {
  private final GhidraSession context;

  MemoryMutations(GhidraSession context) {
    this.context = context;
  }

  void patchMemory(
      String startRaw, ByteSequence sequence, boolean clearExisting, boolean disassemble) {
    Address start = parseAddress(startRaw);
    byte[] bytes =
        MemoryEncoding.decodeBytes(
            sequence.data(), sequence.encoding().name().toLowerCase(java.util.Locale.ROOT));
    if (bytes.length == 0) {
      throw new IllegalArgumentException("byte sequence must not be empty");
    }
    Program program = context.currentProgram();
    Address end = addLengthMinusOne(start, bytes.length);
    requireInitializedRange(program.getMemory(), start, end);

    if (clearExisting) {
      Listing listing = program.getListing();
      CodeUnit tailUnit = listing.getCodeUnitContaining(end);
      Address clearEnd =
          tailUnit != null
                  && isDefinedCodeUnit(tailUnit)
                  && tailUnit.getMaxAddress().compareTo(end) > 0
              ? tailUnit.getMaxAddress()
              : end;
      listing.clearCodeUnits(start, clearEnd, false);
    }

    writeBytes(start, bytes);

    if (disassemble) {
      AddressSet rangeSet = new AddressSet(start, end);
      DisassembleCommand command = new DisassembleCommand(rangeSet, rangeSet, true);
      command.enableCodeAnalysis(false);
      context.runCommand(command, "unable to disassemble written bytes");
    }
  }

  private Address parseAddress(String rawAddress) {
    return context.parseAddress(rawAddress);
  }

  private void writeBytes(Address start, byte[] bytes) {
    try {
      context.script().setBytes(start, bytes);
    } catch (MemoryAccessException ex) {
      throw new TransactionExecutionException("unable to write memory: " + ex.getMessage(), ex);
    }
  }

  private static Address addLengthMinusOne(Address start, int byteLength) {
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

  private static void requireInitializedRange(Memory memory, Address start, Address end) {
    Address current = start;
    while (true) {
      MemoryBlock block = memory.getBlock(current);
      if (block == null || !block.isInitialized()) {
        throw new IllegalArgumentException(
            "address range "
                + AddressUtil.canonicalAddress(start)
                + ".."
                + AddressUtil.canonicalAddress(end)
                + " is not in initialized memory");
      }
      if (block.getEnd().compareTo(end) >= 0) {
        return;
      }
      Address next = block.getEnd().next();
      if (next == null || !next.getAddressSpace().equals(end.getAddressSpace())) {
        throw new IllegalArgumentException(
            "address range "
                + AddressUtil.canonicalAddress(start)
                + ".."
                + AddressUtil.canonicalAddress(end)
                + " is not in initialized memory");
      }
      current = next;
    }
  }

  private static boolean isDefinedCodeUnit(CodeUnit unit) {
    if (unit instanceof Instruction) {
      return true;
    }
    if (unit instanceof Data data) {
      return data.isDefined();
    }
    return false;
  }
}
