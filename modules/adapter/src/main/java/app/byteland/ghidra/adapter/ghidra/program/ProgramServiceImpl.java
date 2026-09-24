package app.byteland.ghidra.adapter.ghidra.program;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.program.AddressSpaceResource;
import app.byteland.ghidra.service.program.ProgramLanguageResource;
import app.byteland.ghidra.service.program.ProgramResource;
import app.byteland.ghidra.service.program.ProgramService;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
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
    int count = 0;
    for (Function function = context.script().getFirstFunction();
        function != null;
        function = context.script().getFunctionAfter(function)) {
      count++;
    }
    return count;
  }

  private int symbolCount() {
    int count = 0;
    for (Symbol symbol = firstSymbol();
        symbol != null;
        symbol = context.script().getSymbolAfter(symbol)) {
      count++;
    }
    return count;
  }

  private Symbol firstSymbol() {
    AddressSpace addressSpace = context.script().getAddressFactory().getDefaultAddressSpace();
    if (addressSpace == null) {
      return null;
    }
    Address start = addressSpace.getMinAddress();
    Symbol symbol = context.script().getSymbolAt(start);
    return symbol == null ? context.script().getSymbolAfter(start) : symbol;
  }
}
