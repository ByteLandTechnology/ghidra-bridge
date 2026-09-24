package app.byteland.ghidra.adapter.ghidra.datatype;

import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.datatype.DataTypeCategoryResource;
import app.byteland.ghidra.service.datatype.DataTypeResource;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.NoSuchElementException;

final class DataTypeQueries {
  private DataTypeQueries() {}

  static Page<DataTypeCategoryResource> listCategories(
      DataTypeManager manager, String categoryPath, int limit, String cursor) {
    String normalizedPath = categoryPath == null || categoryPath.isBlank() ? "/" : categoryPath;
    Category category = manager.getCategory(new CategoryPath(normalizedPath));
    if (category == null) throw new NoSuchElementException("category not found: " + normalizedPath);
    List<DataTypeCategoryResource> all = new ArrayList<>();
    for (Category child : category.getCategories()) {
      all.add(
          new DataTypeCategoryResource(
              child.getCategoryPath().getPath(),
              child.getName(),
              child.getCategories().length,
              child.getDataTypes().length));
    }
    all.sort(Comparator.comparing(DataTypeCategoryResource::path));
    return Page.paginate(all, limit, cursor, DataTypeCategoryResource::path);
  }

  static Page<DataTypeResource> searchDataTypes(
      DataTypeManager manager,
      String query,
      String categoryPath,
      String kind,
      int limit,
      String cursor) {
    String lowerQuery = query == null ? "" : query.toLowerCase(Locale.ROOT);
    List<DataTypeResource> all = new ArrayList<>();
    java.util.Iterator<DataType> iterator = manager.getAllDataTypes();
    while (iterator.hasNext()) {
      DataType dataType = iterator.next();
      if (!dataType.getName().toLowerCase(Locale.ROOT).contains(lowerQuery)) continue;
      DataTypeResource resource = DataTypeDescriptions.summarize(dataType);
      if (categoryPath != null && !categoryPath.equals(resource.categoryPath())) continue;
      if (kind != null && !kind.equalsIgnoreCase(resource.kind().name())) continue;
      all.add(resource);
    }
    all.sort(Comparator.comparing(DataTypeResource::path));
    return Page.paginate(all, limit, cursor, DataTypeResource::path);
  }
}
