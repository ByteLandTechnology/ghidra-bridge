package app.byteland.ghidra.adapter.ghidra.program;

import app.byteland.ghidra.adapter.ghidra.AddressUtil;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.program.AddressSpaceResource;
import app.byteland.ghidra.service.program.ProgramHistoryConflictException;
import app.byteland.ghidra.service.program.ProgramHistoryResource;
import app.byteland.ghidra.service.program.ProgramLanguageResource;
import app.byteland.ghidra.service.program.ProgramResource;
import app.byteland.ghidra.service.program.ProgramService;
import app.byteland.ghidra.service.program.ProgramUndoRedoResult;
import ghidra.framework.model.DomainObject;
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
  public ProgramHistoryResource getHistory() {
    return context.withProgramLock(ProgramServiceImpl::snapshotHistory);
  }

  @Override
  public ProgramUndoRedoResult undo() {
    return context.withIdleProgram(
        activeProgram -> {
          DomainObject domainObject = activeProgram;
          if (!domainObject.canUndo()) {
            throw ProgramHistoryConflictException.nothingToUndo();
          }
          String transactionName = normalizeTransactionName(domainObject.getUndoName());
          domainObject.undo();
          ProgramHistoryResource history = snapshotHistory(domainObject);
          return new ProgramUndoRedoResult(
              "undo",
              transactionName == null ? "" : transactionName,
              history.canUndo(),
              history.canRedo(),
              history.undoName(),
              history.redoName(),
              history.undoList(),
              history.redoList());
        });
  }

  @Override
  public ProgramUndoRedoResult redo() {
    return context.withIdleProgram(
        activeProgram -> {
          DomainObject domainObject = activeProgram;
          if (!domainObject.canRedo()) {
            throw ProgramHistoryConflictException.nothingToRedo();
          }
          String transactionName = normalizeTransactionName(domainObject.getRedoName());
          domainObject.redo();
          ProgramHistoryResource history = snapshotHistory(domainObject);
          return new ProgramUndoRedoResult(
              "redo",
              transactionName == null ? "" : transactionName,
              history.canUndo(),
              history.canRedo(),
              history.undoName(),
              history.redoName(),
              history.undoList(),
              history.redoList());
        });
  }

  private static ProgramHistoryResource snapshotHistory(DomainObject domainObject) {
    boolean canUndo = domainObject.canUndo();
    boolean canRedo = domainObject.canRedo();
    String undoName = canUndo ? normalizeTransactionName(domainObject.getUndoName()) : null;
    String redoName = canRedo ? normalizeTransactionName(domainObject.getRedoName()) : null;
    List<String> undoList = domainObject.getAllUndoNames();
    List<String> redoList = domainObject.getAllRedoNames();
    return new ProgramHistoryResource(
        canUndo,
        canRedo,
        undoName,
        redoName,
        undoList == null ? List.of() : List.copyOf(undoList),
        redoList == null ? List.of() : List.copyOf(redoList));
  }

  private static String normalizeTransactionName(String rawName) {
    return rawName == null || rawName.isBlank() ? null : rawName;
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
