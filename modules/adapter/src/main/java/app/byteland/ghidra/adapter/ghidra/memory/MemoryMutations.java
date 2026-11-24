package app.byteland.ghidra.adapter.ghidra.memory;

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
import ghidra.program.model.mem.MemoryAccessException;
import java.util.Locale;

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
            sequence.data(), sequence.encoding().name().toLowerCase(Locale.ROOT));
    if (bytes.length == 0) {
      writeBytes(start, bytes);
      return;
    }

    Address end = endAddress(start, bytes.length);
    Listing listing = context.currentProgram().getListing();
    if (clearExisting) {
      listing.clearCodeUnits(expandClearStart(listing, start), expandClearEnd(listing, end), false);
    }
    writeBytes(start, bytes);
    if (disassemble) {
      AddressSet range = new AddressSet(start, end);
      DisassembleCommand command = new DisassembleCommand(range, range, true);
      command.enableCodeAnalysis(false);
      context.runCommand(command, "unable to disassemble written memory");
      if (!listing.getInstructions(range, true).hasNext()) {
        throw new TransactionExecutionException(
            "unable to disassemble written memory: no valid instructions in range");
      }
    }
  }

  private Address parseAddress(String rawAddress) {
    return context.parseAddress(rawAddress);
  }

  private static Address endAddress(Address start, int byteCount) {
    if (byteCount <= 1) {
      return start;
    }
    try {
      return start.addNoWrap(byteCount - 1L);
    } catch (AddressOverflowException exception) {
      throw new IllegalArgumentException(
          "memory write exceeds address space bounds", exception);
    }
  }

  private static Address expandClearStart(Listing listing, Address start) {
    CodeUnit first = listing.getCodeUnitContaining(start);
    if (isDefined(first) && first.getMinAddress().compareTo(start) < 0) {
      return first.getMinAddress();
    }
    return start;
  }

  private static Address expandClearEnd(Listing listing, Address end) {
    CodeUnit last = listing.getCodeUnitContaining(end);
    if (isDefined(last) && last.getMaxAddress().compareTo(end) > 0) {
      return last.getMaxAddress();
    }
    return end;
  }

  private static boolean isDefined(CodeUnit codeUnit) {
    if (codeUnit instanceof Instruction) {
      return true;
    }
    return codeUnit instanceof Data data && data.isDefined();
  }

  private void writeBytes(Address start, byte[] bytes) {
    try {
      context.script().setBytes(start, bytes);
    } catch (MemoryAccessException ex) {
      throw new TransactionExecutionException("unable to write memory: " + ex.getMessage(), ex);
    }
  }
}
