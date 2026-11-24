package app.byteland.ghidra.adapter.ghidra.datatype;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.QuerySnapshotCache;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.datatype.DataTypeCategoryResource;
import app.byteland.ghidra.service.datatype.DataTypeResource;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.NoSuchElementException;

final class DataTypeQueries {
  private static final String CATEGORY_RESOURCE = "data_type_category";
  private static final String DATA_TYPE_RESOURCE = "data_type";

  private DataTypeQueries() {}

  static Page<DataTypeCategoryResource> listCategories(
      GhidraSession context,
      DataTypeManager manager,
      String categoryPath,
      int limit,
      String cursor) {
    String normalizedPath = categoryPath == null || categoryPath.isBlank() ? "/" : categoryPath;
    Category category = manager.getCategory(new CategoryPath(normalizedPath));
    if (category == null) throw new NoSuchElementException("category not found: " + normalizedPath);
    boolean hasCursor = cursor != null && !cursor.isBlank();
    if (!hasCursor || context.isAnalyzing()) {
      return selectCategoriesBounded(category, limit, cursor);
    }

    long modNumber = context.modificationNumber();
    String canonicalCategoryPath = category.getCategoryPath().getPath();
    QuerySnapshotCache.Key cacheKey =
        QuerySnapshotCache.Key.of(CATEGORY_RESOURCE, modNumber, canonicalCategoryPath);
    String[] sortedKeys = context.querySnapshots().get(cacheKey);
    if (sortedKeys == null) {
      Category[] children = category.getCategories();
      sortedKeys = new String[children.length];
      for (int i = 0; i < children.length; i++) {
        sortedKeys[i] = children[i].getCategoryPath().getPath();
      }
      Arrays.sort(sortedKeys);
      if (context.isAnalyzing()) {
        return selectCategoriesBounded(category, limit, cursor);
      }
      if (context.modificationNumber() == modNumber) {
        context.querySnapshots().put(cacheKey, sortedKeys);
      }
    }
    return QuerySnapshotCache.slice(
        sortedKeys,
        limit,
        cursor,
        path -> manager.getCategory(new CategoryPath(path)),
        DataTypeQueries::describeCategory);
  }

  static Page<DataTypeResource> searchDataTypes(
      GhidraSession context,
      DataTypeManager manager,
      String query,
      String categoryPath,
      String kind,
      int limit,
      String cursor) {
    String lowerQuery = query == null ? "" : query.toLowerCase(Locale.ROOT);
    DataTypeResource.Kind expectedKind = null;
    String normalizedKind = null;
    if (kind != null) {
      expectedKind = parseKindOrNull(kind);
      if (expectedKind == null) {
        return Page.of(List.of(), Page.clampLimit(limit), null);
      }
      normalizedKind = expectedKind.name();
    }

    boolean hasCursor = cursor != null && !cursor.isBlank();
    if (!hasCursor || context.isAnalyzing()) {
      return selectDataTypesBounded(
          manager, lowerQuery, categoryPath, expectedKind, limit, cursor);
    }

    long modNumber = context.modificationNumber();
    QuerySnapshotCache.Key cacheKey =
        QuerySnapshotCache.Key.of(
            DATA_TYPE_RESOURCE, modNumber, lowerQuery, categoryPath, normalizedKind);
    String[] sortedKeys = context.querySnapshots().get(cacheKey);
    if (sortedKeys == null) {
      List<String> keys = new ArrayList<>();
      Iterator<DataType> iterator = manager.getAllDataTypes();
      while (iterator.hasNext()) {
        DataType dataType = iterator.next();
        if (!matchesDataType(dataType, lowerQuery, categoryPath, expectedKind)) continue;
        keys.add(dataType.getPathName());
      }
      sortedKeys = keys.toArray(String[]::new);
      Arrays.sort(sortedKeys);
      if (context.isAnalyzing()) {
        return selectDataTypesBounded(
            manager, lowerQuery, categoryPath, expectedKind, limit, cursor);
      }
      if (context.modificationNumber() == modNumber) {
        context.querySnapshots().put(cacheKey, sortedKeys);
      }
    }
    return QuerySnapshotCache.slice(
        sortedKeys, limit, cursor, manager::getDataType, DataTypeDescriptions::summarize);
  }

  private static Page<DataTypeCategoryResource> selectCategoriesBounded(
      Category category, int limit, String cursor) {
    Page.Selector<Category> selector = Page.selector(limit, cursor);
    for (Category child : category.getCategories()) {
      String path = child.getCategoryPath().getPath();
      if (selector.acceptsKey(path)) {
        selector.offer(path, child);
      }
    }
    return selector.finish(DataTypeQueries::describeCategory);
  }

  private static DataTypeCategoryResource describeCategory(Category child) {
    return new DataTypeCategoryResource(
        child.getCategoryPath().getPath(),
        child.getName(),
        child.getCategories().length,
        child.getDataTypes().length);
  }

  private static Page<DataTypeResource> selectDataTypesBounded(
      DataTypeManager manager,
      String lowerQuery,
      String categoryPath,
      DataTypeResource.Kind expectedKind,
      int limit,
      String cursor) {
    Page.Selector<DataType> selector = Page.selector(limit, cursor);
    Iterator<DataType> iterator = manager.getAllDataTypes();
    while (iterator.hasNext()) {
      DataType dataType = iterator.next();
      if (!matchesDataType(dataType, lowerQuery, categoryPath, expectedKind)) continue;
      String path = dataType.getPathName();
      if (selector.acceptsKey(path)) {
        selector.offer(path, dataType);
      }
    }
    return selector.finish(DataTypeDescriptions::summarize);
  }

  private static boolean matchesDataType(
      DataType dataType,
      String lowerQuery,
      String categoryPath,
      DataTypeResource.Kind expectedKind) {
    String name = dataType.getName();
    if (!lowerQuery.isEmpty() && !name.toLowerCase(Locale.ROOT).contains(lowerQuery)) {
      return false;
    }
    if (categoryPath != null
        && !categoryPath.equals(
            DataTypeDescriptions.categoryFromPath(dataType.getPathName(), name))) {
      return false;
    }
    return expectedKind == null || expectedKind == DataTypeDescriptions.classifyKind(dataType);
  }

  private static DataTypeResource.Kind parseKindOrNull(String rawKind) {
    for (DataTypeResource.Kind candidate : DataTypeResource.Kind.values()) {
      if (candidate.name().equalsIgnoreCase(rawKind)) {
        return candidate;
      }
    }
    return null;
  }
}
