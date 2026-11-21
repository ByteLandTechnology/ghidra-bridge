package app.byteland.ghidra.adapter.ghidra.datatype;

import app.byteland.ghidra.adapter.ghidra.GhidraCParserSupport;
import app.byteland.ghidra.adapter.ghidra.GhidraDataTypeReferences;
import app.byteland.ghidra.service.datatype.DataTypeMutationValidationException;
import app.byteland.ghidra.service.datatype.DataTypeResource;
import app.byteland.ghidra.service.datatype.DataTypeService;
import app.byteland.ghidra.service.datatype.DataTypeService.ConflictMode;
import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.app.util.cparser.C.TokenMgrError;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.SourceArchive;
import ghidra.program.model.data.StandAloneDataTypeManager;
import ghidra.util.exception.DuplicateNameException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Parses C header declarations with Ghidra {@link CParser} and resolves them into a program.
 */
final class CDeclarationParser {
  private static final String DECLARATIONS_TARGET = "declarations";
  private static final String CATEGORY_PATH_TARGET = "categoryPath";
  private static final String FUNCTIONS_SUBCATEGORY = "functions";

  private CDeclarationParser() {}

  static List<DataTypeResource> parseAndStore(
      DataTypeManager programDataTypeManager,
      String declarations,
      String categoryPath,
      ConflictMode conflictMode) {
    if (declarations == null || declarations.isBlank()) {
      throw new DataTypeMutationValidationException(
          DECLARATIONS_TARGET, "declarations must not be blank");
    }
    int byteLength = declarations.getBytes(StandardCharsets.UTF_8).length;
    if (byteLength > DataTypeService.MAX_DECLARATIONS_BYTES) {
      throw new DataTypeMutationValidationException(
          DECLARATIONS_TARGET,
          "declarations exceeds maximum size of "
              + DataTypeService.MAX_DECLARATIONS_BYTES
              + " UTF-8 bytes");
    }
    CategoryPath targetCategory = parseCategoryPath(categoryPath);
    ConflictMode effectiveMode = conflictMode == null ? ConflictMode.REPLACE : conflictMode;
    DataTypeConflictHandler conflictHandler = toConflictHandler(effectiveMode);

    try (StandAloneDataTypeManager scratch =
            GhidraCParserSupport.createScratchManager(programDataTypeManager);
        StandAloneDataTypeManager stdintFallback =
            GhidraCParserSupport.createStdintFallbackManager(programDataTypeManager)) {
      CParser parser =
          new CParser(
              scratch,
              true,
              GhidraCParserSupport.lookupManagers(programDataTypeManager, stdintFallback));
      parser.setParseFileName("declarations.h");
      try {
        parser.parse(GhidraCParserSupport.normalizeCSource(declarations));
      } catch (ParseException | TokenMgrError | IllegalArgumentException failure) {
        throw new DataTypeMutationValidationException(
            DECLARATIONS_TARGET,
            GhidraCParserSupport.cleanParseMessage(failure, parser.getParseMessages()),
            failure);
      }
      if (!parser.didParseSucceed()) {
        throw new DataTypeMutationValidationException(
            DECLARATIONS_TARGET,
            GhidraCParserSupport.cleanParseMessage(null, parser.getParseMessages()));
      }

      List<DataType> declared = collectDeclaredTypes(scratch, parser);
      if (declared.isEmpty()) {
        throw new DataTypeMutationValidationException(
            DECLARATIONS_TARGET, "declarations did not define any C data types");
      }

      relocateScratchTypes(scratch, targetCategory);
      clearScratchSourceArchives(scratch);
      resolveUsedStdintTypedefs(scratch, programDataTypeManager, stdintFallback);

      List<DataTypeResource> resources = new ArrayList<>(declared.size());
      for (DataType candidate : declared) {
        DataType resolved = programDataTypeManager.resolve(candidate, conflictHandler);
        programDataTypeManager.disassociate(resolved);
        resources.add(DataTypeDescriptions.detail(resolved));
      }
      removeTemporaryArchives(programDataTypeManager, scratch, stdintFallback);
      return List.copyOf(resources);
    }
  }

  private static CategoryPath parseCategoryPath(String rawCategoryPath) {
    if (rawCategoryPath == null || rawCategoryPath.isBlank()) {
      return CategoryPath.ROOT;
    }
    String trimmed = rawCategoryPath.trim();
    if (!trimmed.startsWith("/")) {
      throw new DataTypeMutationValidationException(
          CATEGORY_PATH_TARGET, "category_path must start with '/': " + trimmed);
    }
    try {
      return new CategoryPath(trimmed);
    } catch (IllegalArgumentException error) {
      throw new DataTypeMutationValidationException(
          CATEGORY_PATH_TARGET, "invalid category_path: " + error.getMessage(), error);
    }
  }

  private static DataTypeConflictHandler toConflictHandler(ConflictMode mode) {
    return switch (mode) {
      case REPLACE -> DataTypeConflictHandler.REPLACE_HANDLER;
      case KEEP -> DataTypeConflictHandler.KEEP_HANDLER;
      case RENAME -> DataTypeConflictHandler.DEFAULT_HANDLER;
    };
  }

  private static List<DataType> collectDeclaredTypes(
      StandAloneDataTypeManager scratch, CParser parser) {
    Map<Long, DataType> byId = new LinkedHashMap<>();
    addDeclaredEntries(scratch, parser.getEnums(), byId, false);
    addDeclaredEntries(scratch, parser.getComposites(), byId, false);
    addDeclaredEntries(scratch, parser.getTypes(), byId, false);
    addDeclaredEntries(scratch, parser.getFunctions(), byId, true);
    return List.copyOf(byId.values());
  }

  private static void addDeclaredEntries(
      StandAloneDataTypeManager scratch,
      Map<String, DataType> entries,
      Map<Long, DataType> sink,
      boolean skipShadowedFunctions) {
    if (entries == null || entries.isEmpty()) {
      return;
    }
    SourceArchive localArchive = scratch.getLocalSourceArchive();
    for (DataType candidate : entries.values()) {
      if (candidate == null) {
        continue;
      }
      DataType stored = scratch.getDataType(candidate.getCategoryPath(), candidate.getName());
      DataType selected = stored != null ? stored : candidate;
      if (isSyntheticFunctionPointee(selected)) {
        continue;
      }
      if (skipShadowedFunctions
          && selected instanceof FunctionDefinition
          && scratch.getDataType(CategoryPath.ROOT, selected.getName()) != null) {
        continue;
      }
      SourceArchive archive = selected.getSourceArchive();
      if (archive != null
          && localArchive != null
          && !localArchive.getSourceArchiveID().equals(archive.getSourceArchiveID())) {
        continue;
      }
      long id = scratch.getID(selected);
      if (id >= 0) {
        sink.putIfAbsent(id, selected);
      }
    }
  }

  private static boolean isSyntheticFunctionPointee(DataType dataType) {
    return dataType instanceof FunctionDefinition
        && dataType.getName() != null
        && dataType.getName().startsWith("_func_");
  }

  private static void relocateScratchTypes(
      StandAloneDataTypeManager scratch, CategoryPath targetCategory) {
    if (CategoryPath.ROOT.equals(targetCategory)) {
      return;
    }
    SourceArchive localArchive = scratch.getLocalSourceArchive();
    List<DataType> localTypes = new ArrayList<>();
    Set<String> rootTypeNames = new HashSet<>();
    Iterator<DataType> iterator = scratch.getAllDataTypes();
    while (iterator.hasNext()) {
      DataType candidate = iterator.next();
      SourceArchive archive = candidate.getSourceArchive();
      if (archive != null
          && localArchive != null
          && localArchive.getSourceArchiveID().equals(archive.getSourceArchiveID())) {
        localTypes.add(candidate);
        if (CategoryPath.ROOT.equals(candidate.getCategoryPath())
            && !(candidate instanceof ghidra.program.model.data.Pointer)
            && !(candidate instanceof ghidra.program.model.data.Array)) {
          rootTypeNames.add(candidate.getName());
        }
      }
    }
    int txId = scratch.startTransaction("Relocate parsed C types");
    boolean committed = false;
    try {
      CategoryPath syntheticFunctionsCategory =
          new CategoryPath(targetCategory, FUNCTIONS_SUBCATEGORY);
      for (DataType dataType : localTypes) {
        if (dataType instanceof ghidra.program.model.data.Pointer
            || dataType instanceof ghidra.program.model.data.Array) {
          continue;
        }
        boolean keepInFunctionsSubcategory =
            isSyntheticFunctionPointee(dataType)
                || (dataType instanceof FunctionDefinition
                    && rootTypeNames.contains(dataType.getName()));
        CategoryPath destination =
            keepInFunctionsSubcategory ? syntheticFunctionsCategory : targetCategory;
        if (!destination.equals(dataType.getCategoryPath())) {
          try {
            dataType.setCategoryPath(destination);
          } catch (DuplicateNameException error) {
            throw new DataTypeMutationValidationException(
                DECLARATIONS_TARGET,
                "duplicate data type name in category "
                    + destination.getPath()
                    + ": "
                    + dataType.getName(),
                error);
          }
        }
      }
      committed = true;
    } finally {
      scratch.endTransaction(txId, committed);
    }
  }

  private static void clearScratchSourceArchives(StandAloneDataTypeManager scratch) {
    SourceArchive localArchive = scratch.getLocalSourceArchive();
    if (localArchive == null) {
      return;
    }
    int txId = scratch.startTransaction("Clear scratch source archives");
    boolean committed = false;
    try {
      Iterator<DataType> iterator = scratch.getAllDataTypes();
      while (iterator.hasNext()) {
        DataType candidate = iterator.next();
        SourceArchive archive = candidate.getSourceArchive();
        if (archive != null
            && localArchive.getSourceArchiveID().equals(archive.getSourceArchiveID())) {
          scratch.disassociate(candidate);
        }
      }
      committed = true;
    } finally {
      scratch.endTransaction(txId, committed);
    }
  }

  private static void removeTemporaryArchives(
      DataTypeManager programDataTypeManager,
      StandAloneDataTypeManager scratch,
      StandAloneDataTypeManager stdintFallback) {
    for (StandAloneDataTypeManager temporary : List.of(scratch, stdintFallback)) {
      SourceArchive localArchive = temporary.getLocalSourceArchive();
      if (localArchive == null) {
        continue;
      }
      SourceArchive attached =
          programDataTypeManager.getSourceArchive(localArchive.getSourceArchiveID());
      if (attached != null) {
        programDataTypeManager.removeSourceArchive(attached);
      }
    }
  }

  private static void resolveUsedStdintTypedefs(
      StandAloneDataTypeManager scratch,
      DataTypeManager programDataTypeManager,
      StandAloneDataTypeManager stdintFallback) {
    SourceArchive stdintArchive = stdintFallback.getLocalSourceArchive();
    if (stdintArchive == null) {
      return;
    }
    Iterator<DataType> iterator = scratch.getAllDataTypes();
    while (iterator.hasNext()) {
      DataType candidate = iterator.next();
      SourceArchive archive = candidate.getSourceArchive();
      if (archive != null
          && stdintArchive.getSourceArchiveID().equals(archive.getSourceArchiveID())
          && programDataTypeManager.getDataType(CategoryPath.ROOT, candidate.getName()) == null
          && GhidraDataTypeReferences.findNamed(programDataTypeManager, candidate.getName())
              .isEmpty()) {
        DataType original = stdintFallback.getDataType(CategoryPath.ROOT, candidate.getName());
        if (original instanceof ghidra.program.model.data.TypeDef typeDef) {
          programDataTypeManager.addDataType(
              new ghidra.program.model.data.TypedefDataType(
                  CategoryPath.ROOT,
                  typeDef.getName(),
                  typeDef.getDataType().clone(programDataTypeManager),
                  programDataTypeManager),
              DataTypeConflictHandler.KEEP_HANDLER);
        }
      }
    }
  }
}
