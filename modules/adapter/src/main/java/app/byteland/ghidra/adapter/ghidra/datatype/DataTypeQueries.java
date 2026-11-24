package app.byteland.ghidra.adapter.ghidra.datatype;

import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.datatype.DataTypeCategoryResource;
import app.byteland.ghidra.service.datatype.DataTypeResource;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import java.util.Arrays;
import java.util.Collections;
import java.util.Iterator;
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
    Page.Selector<Category> selector = Page.selector(limit, cursor);
    Category[] children = category.getCategories();
    if (children != null) {
      for (Category child : children) {
        selector.offer(child.getCategoryPath().getPath(), child);
      }
    }
    return selector.finish((child, path) ->
        new DataTypeCategoryResource(
            path, child.getName(), child.getCategories().length, child.getDataTypes().length));
  }

  static Page<DataTypeResource> searchDataTypes(
      DataTypeManager manager,
      String query,
      String categoryPath,
      String kind,
      int limit,
      String cursor) {
    int clamped = Page.clampLimit(limit);
    DataTypeResource.Kind expectedKind = parseKindOrNull(kind);
    if (kind != null && expectedKind == null) {
      return Page.of(List.of(), clamped, null);
    }
    Iterator<DataType> iterator;
    if (categoryPath != null) {
      Category category = resolveCategoryOrNull(manager, categoryPath);
      if (category == null) {
        return Page.of(List.of(), clamped, null);
      }
      DataType[] categoryTypes = category.getDataTypes();
      iterator =
          categoryTypes == null
              ? Collections.emptyIterator()
              : Arrays.asList(categoryTypes).iterator();
    } else {
      iterator = manager.getAllDataTypes();
    }
    String lowerQuery = query == null ? "" : query.toLowerCase(Locale.ROOT);
    Page.Selector<DataType> selector = Page.selector(clamped, cursor);
    while (iterator.hasNext()) {
      DataType dataType = iterator.next();
      String name = dataType.getName();
      if (!lowerQuery.isEmpty() && !name.toLowerCase(Locale.ROOT).contains(lowerQuery)) continue;
      String path = dataType.getPathName();
      if (categoryPath != null
          && !categoryPath.equals(DataTypeDescriptions.categoryFromPath(path, name))) {
        continue;
      }
      if (expectedKind != null && DataTypeDescriptions.classifyKind(dataType) != expectedKind) {
        continue;
      }
      selector.offer(path, dataType);
    }
    return selector.finish(DataTypeDescriptions::summarize);
  }

  private static Category resolveCategoryOrNull(DataTypeManager manager, String categoryPath) {
    if (categoryPath.isEmpty() || !categoryPath.startsWith("/")) {
      return null;
    }
    CategoryPath parsed;
    try {
      parsed = new CategoryPath(categoryPath);
    } catch (IllegalArgumentException invalid) {
      return null;
    }
    if (!categoryPath.equals(parsed.getPath())) {
      return null;
    }
    return manager.getCategory(parsed);
  }

  private static DataTypeResource.Kind parseKindOrNull(String kind) {
    if (kind == null) {
      return null;
    }
    try {
      return DataTypeResource.Kind.valueOf(kind.toUpperCase(Locale.ROOT));
    } catch (IllegalArgumentException unknown) {
      return null;
    }
  }
}
