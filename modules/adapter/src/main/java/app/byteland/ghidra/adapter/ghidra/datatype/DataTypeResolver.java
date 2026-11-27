package app.byteland.ghidra.adapter.ghidra.datatype;

import app.byteland.ghidra.adapter.ghidra.GhidraDataTypeReferences;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import java.util.List;

/**
 * Resolves Ghidra {@link DataType} instances by category path or simple type name.
 */
public final class DataTypeResolver {
  private DataTypeResolver() {}

  /**
   * Resolves a data type by category path or unqualified name in a {@link DataTypeManager}.
   *
   * @param dataTypeManager program data type manager
   * @param typeName category path or simple data type name
   * @return resolved {@link DataType}, or {@code null} when not found
   */
  public static DataType resolve(DataTypeManager dataTypeManager, String typeName) {
    if (typeName == null || typeName.isBlank()) {
      return null;
    }

    String absolutePath = typeName.startsWith("/") ? typeName : "/" + typeName;
    String simpleName =
        absolutePath.lastIndexOf('/') < absolutePath.length() - 1
            ? absolutePath.substring(absolutePath.lastIndexOf('/') + 1)
            : typeName;
    DataType byPath = GhidraDataTypeReferences.findByPath(dataTypeManager, absolutePath);
    if (byPath != null) {
      return byPath;
    }

    boolean explicitPath = typeName.startsWith("/") || typeName.indexOf('/') >= 0;
    if (explicitPath) {
      return null;
    }

    List<DataType> matches = GhidraDataTypeReferences.findNamed(dataTypeManager, simpleName);
    return matches.isEmpty() ? null : matches.getFirst();
  }
}
