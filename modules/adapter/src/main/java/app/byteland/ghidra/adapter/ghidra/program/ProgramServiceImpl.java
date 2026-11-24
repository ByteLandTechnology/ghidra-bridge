package app.byteland.ghidra.adapter.ghidra.program;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.program.AddressSpaceResource;
import app.byteland.ghidra.service.program.ProgramConflictException;
import app.byteland.ghidra.service.program.ProgramLanguageResource;
import app.byteland.ghidra.service.program.ProgramResource;
import app.byteland.ghidra.service.program.ProgramService;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Program;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public final class ProgramServiceImpl implements ProgramService {
  private final Program program;
  private final GhidraSession context;

  public ProgramServiceImpl(GhidraSession context) {
    this.context = Objects.requireNonNull(context, "context");
    this.program = context.currentProgram();
  }

  @Override
  public ProgramResource getProgram() {
    return new ProgramResource(
        program.getName(),
        program.getExecutablePath(),
        program.getExecutableFormat(),
        AddressUtil.canonicalAddress(program.getImageBase()),
        AddressUtil.canonicalAddress(program.getMinAddress()),
        AddressUtil.canonicalAddress(program.getMaxAddress()),
        String.valueOf(program.getLanguageID()),
        String.valueOf(program.getCompilerSpec().getCompilerSpecID()),
        ProgramTimestamps.createdTimestamp(program),
        ProgramTimestamps.modifiedTimestamp(program),
        functionCount(),
        symbolCount());
  }

  @Override
  public Page<AddressSpaceResource> getAddressSpaces(int limit, String cursor) {
    var addressFactory = context.script().getAddressFactory();
    var defaultSpace = addressFactory.getDefaultAddressSpace();
    List<AddressSpaceResource> list = new ArrayList<>();
    for (AddressSpace space : addressFactory.getAddressSpaces()) {
      list.add(
          new AddressSpaceResource(
              space.getName(),
              describeAddressSpaceType(space),
              space.getPointerSize() * 8,
              AddressUtil.canonicalAddress(space.getMinAddress()),
              AddressUtil.canonicalAddress(space.getMaxAddress()),
              defaultSpace != null && defaultSpace.equals(space)));
    }
    list.sort(java.util.Comparator.comparing(AddressSpaceResource::name));
    return Page.paginate(list, limit, cursor, AddressSpaceResource::name);
  }

  @Override
  public ProgramLanguageResource getLanguageInfo() {
    Language language = program.getLanguage();
    CompilerSpec compilerSpec = program.getCompilerSpec();
    if (language == null || compilerSpec == null) {
      throw new IllegalStateException("program language and compiler spec are required");
    }
    return new ProgramLanguageResource(
        String.valueOf(program.getLanguageID()),
        String.valueOf(compilerSpec.getCompilerSpecID()),
        language.getProcessor().toString(),
        language.isBigEndian()
            ? ProgramLanguageResource.Endian.BIG
            : ProgramLanguageResource.Endian.LITTLE,
        language.getLanguageDescription().getSize());
  }

  @Override
  public void saveProgram() {
    context.saveCurrentProgram();
  }

  @Override
  public ProgramResource rebaseProgram(String imageBaseRaw) {
    Address imageBase = context.parseAddress(imageBaseRaw);
    try {
      program.setImageBase(imageBase, true);
    } catch (AddressOverflowException ex) {
      throw new ProgramConflictException(
          "address_overflow",
          "/image_base",
          "image base overflows address space: " + ex.getMessage(),
          ex);
    } catch (LockException | IllegalStateException ex) {
      throw new ProgramConflictException(
          "rebase_conflict",
          "/image_base",
          "unable to rebase program: " + ex.getMessage(),
          ex);
    }
    return getProgram();
  }

  private static AddressSpaceResource.Kind describeAddressSpaceType(AddressSpace space) {
    if (space.isLoadedMemorySpace()) {
      return AddressSpaceResource.Kind.RAM;
    }
    if (space.isNonLoadedMemorySpace()) {
      return AddressSpaceResource.Kind.NON_LOADED;
    }
    if (space.isRegisterSpace()) {
      return AddressSpaceResource.Kind.REGISTER;
    }
    if (space.isStackSpace()) {
      return AddressSpaceResource.Kind.STACK;
    }
    if (space.isExternalSpace()) {
      return AddressSpaceResource.Kind.EXTERNAL;
    }
    if (space.isConstantSpace()) {
      return AddressSpaceResource.Kind.CONSTANT;
    }
    if (space.isUniqueSpace()) {
      return AddressSpaceResource.Kind.UNIQUE;
    }
    return AddressSpaceResource.Kind.OTHER;
  }

  private int functionCount() {
    return program.getFunctionManager().getFunctionCount();
  }

  private int symbolCount() {
    return program.getSymbolTable().getNumSymbols();
  }
}
