package app.byteland.ghidra.adapter.ghidra;

import ghidra.app.services.DataTypeQueryService;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataOrganization;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.data.SourceArchive;
import ghidra.program.model.data.StandAloneDataTypeManager;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.TypedefDataType;
import ghidra.util.UniversalID;
import ghidra.util.task.TaskMonitor;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Temporary isolated scratch and C99 standard-integer archives closed automatically after each C
 * parse operation.
 */
public final class CParserScratchEnvironment implements AutoCloseable {
  private final DataTypeManager programManager;
  private final StandAloneDataTypeManager scratch;
  private final StandAloneDataTypeManager stdintArchive;
  private final int scratchTx;

  private CParserScratchEnvironment(
      DataTypeManager programManager,
      StandAloneDataTypeManager scratch,
      StandAloneDataTypeManager stdintArchive,
      int scratchTx) {
    this.programManager = programManager;
    this.scratch = scratch;
    this.stdintArchive = stdintArchive;
    this.scratchTx = scratchTx;
  }

  public static CParserScratchEnvironment open(DataTypeManager programManager) {
    DataOrganization organization = programManager.getDataOrganization();
    StandAloneDataTypeManager stdint = buildStdintArchive(organization);
    StandAloneDataTypeManager scratch =
        new StandAloneDataTypeManager("c_parser_scratch", organization);
    int tx = scratch.startTransaction("parse_c");
    return new CParserScratchEnvironment(programManager, scratch, stdint, tx);
  }

  public DataTypeManager programManager() {
    return programManager;
  }

  public StandAloneDataTypeManager scratch() {
    return scratch;
  }

  public DataType stdintType(String name) {
    return stdintArchive.getDataType(CategoryPath.ROOT, name);
  }

  public DataTypeManager[] cParserSubArchives() {
    return new DataTypeManager[] {
      BuiltInDataTypeManager.getDataTypeManager(), programManager, stdintArchive
    };
  }

  public void clearScratchSourceArchives() {
    SourceArchive scratchArchive = scratch.getLocalSourceArchive();
    if (scratchArchive == null) {
      return;
    }
    UniversalID scratchId = scratchArchive.getSourceArchiveID();
    List<DataType> snapshot = new ArrayList<>();
    scratch.getAllDataTypes(snapshot);
    for (DataType candidate : snapshot) {
      SourceArchive archive = candidate.getSourceArchive();
      if (archive != null && scratchId.equals(archive.getSourceArchiveID())) {
        scratch.disassociate(candidate);
      }
    }
  }

  public void resolveUsedStdintTypedefs(DataTypeManager targetManager) {
    SourceArchive stdArchive = stdintArchive.getLocalSourceArchive();
    if (stdArchive == null) {
      return;
    }
    UniversalID stdId = stdArchive.getSourceArchiveID();
    List<DataType> snapshot = new ArrayList<>();
    scratch.getAllDataTypes(snapshot);
    for (DataType candidate : snapshot) {
      SourceArchive archive = candidate.getSourceArchive();
      boolean fromStdArchive = archive != null && stdId.equals(archive.getSourceArchiveID());
      if (fromStdArchive) {
        scratch.disassociate(candidate);
      }
      if (fromStdArchive
          && candidate instanceof TypeDef typeDef
          && targetManager.getDataType(CategoryPath.ROOT, typeDef.getName()) == null) {
        DataType base = GhidraCParserSupport.detachFromScratch(targetManager, typeDef.getDataType());
        DataType resolved =
            targetManager.resolve(
                new TypedefDataType(CategoryPath.ROOT, typeDef.getName(), base, targetManager),
                DataTypeConflictHandler.KEEP_HANDLER);
        targetManager.disassociate(resolved);
      }
    }
  }

  public void removeTemporaryArchives(DataTypeManager targetManager) {
    removeSourceArchiveIfPresent(targetManager, scratch.getLocalSourceArchive());
    removeSourceArchiveIfPresent(targetManager, stdintArchive.getLocalSourceArchive());
  }

  private static void removeSourceArchiveIfPresent(
      DataTypeManager targetManager, SourceArchive temporaryArchive) {
    if (temporaryArchive == null) {
      return;
    }
    SourceArchive attached =
        targetManager.getSourceArchive(temporaryArchive.getSourceArchiveID());
    if (attached != null) {
      targetManager.removeSourceArchive(attached);
    }
  }

  public DataTypeQueryService queryService() {
    List<DataTypeManager> managers =
        List.of(programManager, BuiltInDataTypeManager.getDataTypeManager(), stdintArchive);
    return new DataTypeQueryService() {
      @Override
      public List<DataType> getSortedDataTypeList() {
        List<DataType> all = new ArrayList<>();
        for (DataTypeManager manager : managers) {
          manager.getAllDataTypes(all);
        }
        return all;
      }

      @Override
      public List<CategoryPath> getSortedCategoryPathList() {
        return List.of(CategoryPath.ROOT);
      }

      @Override
      @SuppressWarnings({"deprecation", "removal"})
      public DataType getDataType(String filterText) {
        if (filterText == null || filterText.isBlank()) {
          return null;
        }
        if (filterText.startsWith("/")) {
          for (DataTypeManager manager : managers) {
            DataType byPath = manager.getDataType(filterText);
            if (byPath != null) return byPath;
          }
        }
        for (DataTypeManager manager : managers) {
          List<DataType> matches = new ArrayList<>();
          manager.findDataTypes(filterText, matches);
          if (!matches.isEmpty()) {
            return matches.getFirst();
          }
        }
        return null;
      }

      @Override
      public DataType promptForDataType(String filterText) {
        return getDataType(filterText);
      }

      @Override
      public List<DataType> findDataTypes(String name, TaskMonitor monitor) {
        List<DataType> matches = new ArrayList<>();
        for (DataTypeManager manager : managers) {
          manager.findDataTypes(name, matches);
          if (!matches.isEmpty()) {
            return matches;
          }
        }
        return matches;
      }

      @Override
      public List<DataType> getDataTypesByPath(DataTypePath path) {
        List<DataType> matches = new ArrayList<>();
        for (DataTypeManager manager : managers) {
          DataType found = manager.getDataType(path);
          if (found != null) {
            matches.add(found);
          }
        }
        return matches;
      }

      @Override
      public DataType getProgramDataTypeByPath(DataTypePath path) {
        return programManager.getDataType(path);
      }
    };
  }

  @Override
  public void close() {
    try {
      scratch.endTransaction(scratchTx, false);
    } finally {
      try {
        scratch.close();
      } finally {
        stdintArchive.close();
      }
    }
  }

  private static StandAloneDataTypeManager buildStdintArchive(DataOrganization organization) {
    StandAloneDataTypeManager archive =
        new StandAloneDataTypeManager("c_std_types", organization);
    int tx = archive.startTransaction("init_std_types");
    boolean ok = false;
    try {
      int pointerSize = Math.max(organization.getPointerSize(), 1);
      Map<String, DataType> definitions =
          Map.ofEntries(
              Map.entry("int8_t", AbstractIntegerDataType.getSignedDataType(1, archive)),
              Map.entry("uint8_t", AbstractIntegerDataType.getUnsignedDataType(1, archive)),
              Map.entry("int16_t", AbstractIntegerDataType.getSignedDataType(2, archive)),
              Map.entry("uint16_t", AbstractIntegerDataType.getUnsignedDataType(2, archive)),
              Map.entry("int32_t", AbstractIntegerDataType.getSignedDataType(4, archive)),
              Map.entry("uint32_t", AbstractIntegerDataType.getUnsignedDataType(4, archive)),
              Map.entry("int64_t", AbstractIntegerDataType.getSignedDataType(8, archive)),
              Map.entry("uint64_t", AbstractIntegerDataType.getUnsignedDataType(8, archive)),
              Map.entry(
                  "size_t", AbstractIntegerDataType.getUnsignedDataType(pointerSize, archive)),
              Map.entry("ssize_t", AbstractIntegerDataType.getSignedDataType(pointerSize, archive)),
              Map.entry(
                  "uintptr_t", AbstractIntegerDataType.getUnsignedDataType(pointerSize, archive)),
              Map.entry(
                  "intptr_t", AbstractIntegerDataType.getSignedDataType(pointerSize, archive)),
              Map.entry(
                  "ptrdiff_t", AbstractIntegerDataType.getSignedDataType(pointerSize, archive)));
      for (Map.Entry<String, DataType> entry : definitions.entrySet()) {
        archive.addDataType(
            new TypedefDataType(CategoryPath.ROOT, entry.getKey(), entry.getValue(), archive),
            DataTypeConflictHandler.DEFAULT_HANDLER);
      }
      ok = true;
    } finally {
      archive.endTransaction(tx, ok);
    }
    return archive;
  }
}
