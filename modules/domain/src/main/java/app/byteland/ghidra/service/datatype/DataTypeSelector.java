package app.byteland.ghidra.service.datatype;

/**
 * Selects a data type by full path or by bare name and optional category path.
 */
public sealed interface DataTypeSelector
    permits DataTypeSelector.ByPath, DataTypeSelector.ByName {
  /**
   * Selects a data type by full path or single-token path string.
   */
  record ByPath(String path) implements DataTypeSelector {
    public ByPath {
      if (path == null || path.isBlank()) {
        throw new IllegalArgumentException("path is required");
      }
    }
  }

  /**
   * Selects a data type by bare name and optional category path.
   */
  record ByName(String name, String categoryPath) implements DataTypeSelector {
    public ByName {
      if (name == null || name.isBlank()) {
        throw new IllegalArgumentException("name is required");
      }
    }
  }
}
