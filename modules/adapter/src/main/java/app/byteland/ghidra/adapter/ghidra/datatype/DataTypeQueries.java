package app.byteland.ghidra.adapter.ghidra.datatype;

import app.byteland.ghidra.adapter.ghidra.FieldProjections;
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
import java.util.Set;

final class DataTypeQueries {
  private DataTypeQueries() {}

  static Page<DataTypeCategoryResource> listCategories(
      DataTypeManager manager, String categoryPath, int limit, String cursor) {
    return listCategories(manager, categoryPath, limit, cursor, null);
  }

  static Page<DataTypeCategoryResource> listCategories(
      DataTypeManager manager,
      String categoryPath,
      int limit,
      String cursor,
      Set<String> fields) {
    String normalizedPath = categoryPath == null || categoryPath.isBlank() ? "/" : categoryPath;
    Category category = manager.getCategory(new CategoryPath(normalizedPath));
    if (category == null) throw new NoSuchElementException("category not found: " + normalizedPath);
    List<CategoryEntry> entries = new ArrayList<>();
    for (Category child : category.getCategories()) {
      entries.add(new CategoryEntry(child.getCategoryPath().getPath(), child));
    }
    entries.sort(Comparator.comparing(CategoryEntry::path));
    Page<CategoryEntry> page = Page.paginate(entries, limit, cursor, CategoryEntry::path);
    boolean needName = FieldProjections.allows(fields, "name");
    boolean needCategoryCount = FieldProjections.allows(fields, "category_count");
    boolean needDataTypeCount = FieldProjections.allows(fields, "data_type_count");
    List<DataTypeCategoryResource> items = new ArrayList<>(page.items().size());
    for (CategoryEntry entry : page.items()) {
      Category child = entry.category();
      items.add(
          new DataTypeCategoryResource(
              entry.path(),
              needName ? child.getName() : null,
              needCategoryCount ? child.getCategories().length : 0,
              needDataTypeCount ? child.getDataTypes().length : 0));
    }
    return Page.of(items, page.limit(), page.nextCursor());
  }

  static Page<DataTypeResource> searchDataTypes(
      DataTypeManager manager,
      String query,
      String categoryPath,
      String kind,
      int limit,
      String cursor) {
    return searchDataTypes(manager, query, categoryPath, kind, limit, cursor, null);
  }

  static Page<DataTypeResource> searchDataTypes(
      DataTypeManager manager,
      String query,
      String categoryPath,
      String kind,
      int limit,
      String cursor,
      Set<String> fields) {
    String lowerQuery = query == null ? "" : query.toLowerCase(Locale.ROOT);
    List<DataTypeEntry> matching = new ArrayList<>();
    java.util.Iterator<DataType> iterator = manager.getAllDataTypes();
    while (iterator.hasNext()) {
      DataType dataType = iterator.next();
      String name = dataType.getName();
      if (!name.toLowerCase(Locale.ROOT).contains(lowerQuery)) continue;
      String path = dataType.getPathName();
      if (categoryPath != null
          && !categoryPath.equals(DataTypeDescriptions.categoryFromPath(path, name))) continue;
      if (kind != null
          && !kind.equalsIgnoreCase(DataTypeDescriptions.classifyKind(dataType).name())) continue;
      matching.add(new DataTypeEntry(path, dataType));
    }
    matching.sort(Comparator.comparing(DataTypeEntry::path));
    Page<DataTypeEntry> page = Page.paginate(matching, limit, cursor, DataTypeEntry::path);
    List<DataTypeResource> items = new ArrayList<>(page.items().size());
    for (DataTypeEntry entry : page.items()) {
      items.add(DataTypeDescriptions.summarize(entry.dataType(), fields));
    }
    return Page.of(items, page.limit(), page.nextCursor());
  }

  private record CategoryEntry(String path, Category category) {}

  private record DataTypeEntry(String path, DataType dataType) {}
}
