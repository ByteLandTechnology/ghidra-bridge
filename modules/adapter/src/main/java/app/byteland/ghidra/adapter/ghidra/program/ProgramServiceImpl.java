package app.byteland.ghidra.adapter.ghidra.program;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.FieldProjections;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.program.AddressSpaceResource;
import app.byteland.ghidra.service.program.ProgramLanguageResource;
import app.byteland.ghidra.service.program.ProgramResource;
import app.byteland.ghidra.service.program.ProgramService;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Program;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Set;

public final class ProgramServiceImpl implements ProgramService {
  private final GhidraSession context;

  public ProgramServiceImpl(GhidraSession context) {
    this.context = Objects.requireNonNull(context, "context");
  }

  @Override
  public ProgramResource getProgram() {
    return getProgram(null);
  }

  @Override
  public ProgramResource getProgram(Set<String> fields) {
    Program program = context.currentProgram();
    return new ProgramResource(
        FieldProjections.allows(fields, "name") ? program.getName() : null,
        FieldProjections.allows(fields, "executable_path") ? program.getExecutablePath() : null,
        FieldProjections.allows(fields, "executable_format")
            ? program.getExecutableFormat()
            : null,
        FieldProjections.allows(fields, "image_base")
            ? AddressUtil.canonicalAddress(program.getImageBase())
            : null,
        FieldProjections.allows(fields, "min_address")
            ? AddressUtil.canonicalAddress(program.getMinAddress())
            : null,
        FieldProjections.allows(fields, "max_address")
            ? AddressUtil.canonicalAddress(program.getMaxAddress())
            : null,
        FieldProjections.allows(fields, "language_id")
            ? String.valueOf(program.getLanguageID())
            : null,
        FieldProjections.allows(fields, "compiler_spec_id")
            ? String.valueOf(program.getCompilerSpec().getCompilerSpecID())
            : null,
        FieldProjections.allows(fields, "created_at")
            ? ProgramTimestamps.createdTimestamp(program)
            : null,
        FieldProjections.allows(fields, "modified_at")
            ? ProgramTimestamps.modifiedTimestamp(program)
            : null,
        FieldProjections.allows(fields, "function_count") ? functionCount(program) : 0L,
        FieldProjections.allows(fields, "symbol_count") ? symbolCount(program) : 0L);
  }

  @Override
  public Page<AddressSpaceResource> getAddressSpaces(int limit, String cursor) {
    return getAddressSpaces(limit, cursor, null);
  }

  @Override
  public Page<AddressSpaceResource> getAddressSpaces(
      int limit, String cursor, Set<String> fields) {
    var addressFactory = context.currentProgram().getAddressFactory();
    boolean needDefault = FieldProjections.allows(fields, "default");
    var defaultSpace = needDefault ? addressFactory.getDefaultAddressSpace() : null;
    List<SpaceEntry> entries = new ArrayList<>();
    for (AddressSpace space : addressFactory.getAddressSpaces()) {
      entries.add(new SpaceEntry(space.getName(), space));
    }
    entries.sort(Comparator.comparing(SpaceEntry::name));
    Page<SpaceEntry> page = Page.paginate(entries, limit, cursor, SpaceEntry::name);
    boolean needKind = FieldProjections.allows(fields, "kind");
    boolean needSize = FieldProjections.allows(fields, "size");
    boolean needMinAddress = FieldProjections.allows(fields, "min_address");
    boolean needMaxAddress = FieldProjections.allows(fields, "max_address");
    List<AddressSpaceResource> items = new ArrayList<>(page.items().size());
    for (SpaceEntry entry : page.items()) {
      AddressSpace space = entry.space();
      items.add(
          new AddressSpaceResource(
              entry.name(),
              needKind ? describeAddressSpaceType(space) : null,
              needSize ? space.getPointerSize() * 8 : 0,
              needMinAddress ? AddressUtil.canonicalAddress(space.getMinAddress()) : null,
              needMaxAddress ? AddressUtil.canonicalAddress(space.getMaxAddress()) : null,
              needDefault && defaultSpace != null && defaultSpace.equals(space)));
    }
    return Page.of(items, page.limit(), page.nextCursor());
  }

  @Override
  public ProgramLanguageResource getLanguageInfo() {
    return getLanguageInfo(null);
  }

  @Override
  public ProgramLanguageResource getLanguageInfo(Set<String> fields) {
    Program program = context.currentProgram();
    Language language = program.getLanguage();
    CompilerSpec compilerSpec = program.getCompilerSpec();
    if (language == null || compilerSpec == null) {
      throw new IllegalStateException("program language and compiler spec are required");
    }
    return new ProgramLanguageResource(
        FieldProjections.allows(fields, "language_id")
            ? String.valueOf(program.getLanguageID())
            : null,
        FieldProjections.allows(fields, "compiler_spec_id")
            ? String.valueOf(compilerSpec.getCompilerSpecID())
            : null,
        FieldProjections.allows(fields, "processor") ? language.getProcessor().toString() : null,
        FieldProjections.allows(fields, "endian")
            ? (language.isBigEndian()
                ? ProgramLanguageResource.Endian.BIG
                : ProgramLanguageResource.Endian.LITTLE)
            : null,
        FieldProjections.allows(fields, "address_size")
            ? language.getLanguageDescription().getSize()
            : 0);
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

  private static int functionCount(Program program) {
    return program.getFunctionManager().getFunctionCount();
  }

  private static int symbolCount(Program program) {
    return program.getSymbolTable().getNumSymbols();
  }

  private record SpaceEntry(String name, AddressSpace space) {}
}
