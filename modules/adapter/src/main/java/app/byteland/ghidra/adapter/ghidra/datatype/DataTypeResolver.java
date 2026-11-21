package app.byteland.ghidra.adapter.ghidra.datatype;

import app.byteland.ghidra.adapter.ghidra.GhidraDataTypeReferences;
import app.byteland.ghidra.service.AmbiguousTargetException;
import app.byteland.ghidra.service.datatype.DataTypeSelector;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public final class DataTypeResolver {
  private DataTypeResolver() {}

  public static DataType resolve(DataTypeManager dataTypeManager, String typeName) {
    if (typeName == null || typeName.isBlank()) {
      return null;
    }
    return resolve(dataTypeManager, new DataTypeSelector.ByPath(typeName), "/selector");
  }

  public static DataType resolve(
      DataTypeManager dataTypeManager, DataTypeSelector selector, String errorTarget) {
    if (selector == null) {
      return null;
    }
    return switch (selector) {
      case DataTypeSelector.ByPath byPath -> resolvePathOrBareName(
          dataTypeManager, byPath.path(), errorTarget);
      case DataTypeSelector.ByName byName -> resolveByName(
          dataTypeManager, byName.name(), byName.categoryPath(), errorTarget);
    };
  }

  private static DataType resolvePathOrBareName(
      DataTypeManager dataTypeManager, String pathOrName, String errorTarget) {
    String trimmed = pathOrName.trim();
    if (trimmed.startsWith("/") || trimmed.indexOf('/') >= 0) {
      String absolutePath = trimmed.startsWith("/") ? trimmed : "/" + trimmed;
      return GhidraDataTypeReferences.findByPath(dataTypeManager, absolutePath);
    }
    return resolveBareName(dataTypeManager, trimmed, errorTarget);
  }

  private static DataType resolveByName(
      DataTypeManager dataTypeManager, String name, String categoryPath, String errorTarget) {
    String trimmedName = name.trim();
    if (categoryPath != null && !categoryPath.isBlank()) {
      String cat = categoryPath.trim();
      if (!cat.startsWith("/")) {
        cat = "/" + cat;
      }
      String fullPath =
          "/".equals(cat)
              ? "/" + trimmedName
              : (cat.endsWith("/") ? cat + trimmedName : cat + "/" + trimmedName);
      return GhidraDataTypeReferences.findByPath(dataTypeManager, fullPath);
    }
    if (trimmedName.startsWith("/")) {
      return GhidraDataTypeReferences.findByPath(dataTypeManager, trimmedName);
    }
    return resolveBareName(dataTypeManager, trimmedName, errorTarget);
  }

  private static DataType resolveBareName(
      DataTypeManager dataTypeManager, String bareName, String errorTarget) {
    List<DataType> programRaw = new ArrayList<>();
    dataTypeManager.findDataTypes(bareName, programRaw);
    Map<String, DataType> programMatches = deduplicateByPath(programRaw);
    if (programMatches.size() > 1) {
      throw new AmbiguousTargetException(
          "ambiguous_data_type",
          "multiple data types match '" + bareName + "'; set category_path or path",
          errorTarget,
          List.copyOf(programMatches.keySet()));
    }
    if (programMatches.size() == 1) {
      return programMatches.values().iterator().next();
    }

    List<DataType> builtInRaw = new ArrayList<>();
    BuiltInDataTypeManager.getDataTypeManager().findDataTypes(bareName, builtInRaw);
    Map<String, DataType> builtInMatches = deduplicateByPath(builtInRaw);
    if (builtInMatches.size() > 1) {
      throw new AmbiguousTargetException(
          "ambiguous_data_type",
          "multiple built-in data types match '" + bareName + "'; set category_path or path",
          errorTarget,
          List.copyOf(builtInMatches.keySet()));
    }
    if (builtInMatches.size() == 1) {
      return builtInMatches.values().iterator().next();
    }

    return GhidraDataTypeReferences.findByPath(dataTypeManager, "/" + bareName);
  }

  private static Map<String, DataType> deduplicateByPath(List<DataType> items) {
    Map<String, DataType> byPath = new TreeMap<>();
    for (DataType item : items) {
      String path = item.getPathName();
      if (path != null && !path.isBlank()) {
        byPath.putIfAbsent(path.startsWith("/") ? path : "/" + path, item);
      }
    }
    return byPath;
  }
}
