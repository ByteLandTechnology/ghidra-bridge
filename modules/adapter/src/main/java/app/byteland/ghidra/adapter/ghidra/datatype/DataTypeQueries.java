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
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.NoSuchElementException;

final class DataTypeQueries {
  private static final String CATEGORY_RESOURCE = "data_type_category";
  private static final String DATA_TYPE_RESOURCE = "data_type";

  private DataTypeQueries() {}

  static Page<DataTypeCategoryResource> listCategories(
      DataTypeManager manager, String categoryPath, int limit, String cursor) {
    return listCategories(null, manager, categoryPath, limit, cursor);
  }

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
    if (!hasCursor || context == null || !context.canCacheSnapshots()) {
      return selectCategoriesBounded(category, limit, cursor);
    }

    long modNumber = context.modificationNumber();
    String canonicalCategoryPath = category.getCategoryPath().getPath();
    QuerySnapshotCache.Key cacheKey =
        QuerySnapshotCache.Key.of(CATEGORY_RESOURCE, modNumber, canonicalCategoryPath);
    String[] sortedKeys = context.querySnapshots().get(cacheKey);
    if (sortedKeys == null) {
      Category[] children = category.getCategories();
      if (children == null) {
        sortedKeys = new String[0];
      } else {
        sortedKeys = new String[children.length];
        for (int i = 0; i < children.length; i++) {
          sortedKeys[i] = children[i].getCategoryPath().getPath();
        }
        Arrays.sort(sortedKeys);
      }
      if (!context.canCacheSnapshots()) {
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
      DataTypeManager manager,
      String query,
      String categoryPath,
      String kind,
      int limit,
      String cursor) {
    return searchDataTypes(null, manager, query, categoryPath, kind, limit, cursor);
  }

  static Page<DataTypeResource> searchDataTypes(
      GhidraSession context,
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
    Category scopedCategory = null;
    if (categoryPath != null) {
      scopedCategory = resolveCategoryOrNull(manager, categoryPath);
      if (scopedCategory == null) {
        return Page.of(List.of(), clamped, null);
      }
    }
    String lowerQuery = query == null ? "" : query.toLowerCase(Locale.ROOT);
    String normalizedKind = expectedKind == null ? null : expectedKind.name();

    boolean hasCursor = cursor != null && !cursor.isBlank();
    if (!hasCursor || context == null || !context.canCacheSnapshots()) {
      return selectDataTypesBounded(
          candidateIterator(manager, scopedCategory),
          lowerQuery,
          categoryPath,
          expectedKind,
          clamped,
          cursor);
    }

    long modNumber = context.modificationNumber();
    QuerySnapshotCache.Key cacheKey =
        QuerySnapshotCache.Key.of(
            DATA_TYPE_RESOURCE, modNumber, lowerQuery, categoryPath, normalizedKind);
    String[] sortedKeys = context.querySnapshots().get(cacheKey);
    if (sortedKeys == null) {
      List<String> keys = new ArrayList<>();
      Iterator<DataType> iterator = candidateIterator(manager, scopedCategory);
      while (iterator.hasNext()) {
        String path = matchingDataTypePath(iterator.next(), lowerQuery, categoryPath, expectedKind);
        if (path != null) {
          keys.add(path);
        }
      }
      sortedKeys = keys.toArray(String[]::new);
      Arrays.sort(sortedKeys);
      if (!context.canCacheSnapshots()) {
        return selectDataTypesBounded(
            candidateIterator(manager, scopedCategory),
            lowerQuery,
            categoryPath,
            expectedKind,
            clamped,
            cursor);
      }
      if (context.modificationNumber() == modNumber) {
        context.querySnapshots().put(cacheKey, sortedKeys);
      }
    }
    return QuerySnapshotCache.slice(
        sortedKeys, clamped, cursor, manager::getDataType, DataTypeDescriptions::summarize);
  }

  private static Iterator<DataType> candidateIterator(
      DataTypeManager manager, Category scopedCategory) {
    if (scopedCategory == null) {
      return manager.getAllDataTypes();
    }
    DataType[] categoryTypes = scopedCategory.getDataTypes();
    return categoryTypes == null
        ? Collections.emptyIterator()
        : Arrays.asList(categoryTypes).iterator();
  }

  private static Page<DataTypeCategoryResource> selectCategoriesBounded(
      Category category, int limit, String cursor) {
    Page.Selector<Category> selector = Page.selector(limit, cursor);
    Category[] children = category.getCategories();
    if (children != null) {
      for (Category child : children) {
        selector.offer(child.getCategoryPath().getPath(), child);
      }
    }
    return selector.finish(DataTypeQueries::describeCategory);
  }

  private static DataTypeCategoryResource describeCategory(Category child, String path) {
    return new DataTypeCategoryResource(
        path,
        child.getName(),
        child.getCategories().length,
        child.getDataTypes().length);
  }

  private static Page<DataTypeResource> selectDataTypesBounded(
      Iterator<DataType> iterator,
      String lowerQuery,
      String categoryPath,
      DataTypeResource.Kind expectedKind,
      int clampedLimit,
      String cursor) {
    Page.Selector<DataType> selector = Page.selector(clampedLimit, cursor);
    while (iterator.hasNext()) {
      DataType dataType = iterator.next();
      String path = matchingDataTypePath(dataType, lowerQuery, categoryPath, expectedKind);
      if (path != null) {
        selector.offer(path, dataType);
      }
    }
    return selector.finish(DataTypeDescriptions::summarize);
  }

  private static String matchingDataTypePath(
      DataType dataType,
      String lowerQuery,
      String categoryPath,
      DataTypeResource.Kind expectedKind) {
    String name = dataType.getName();
    if (!lowerQuery.isEmpty() && !name.toLowerCase(Locale.ROOT).contains(lowerQuery)) {
      return null;
    }
    String path = dataType.getPathName();
    if (categoryPath != null
        && !categoryPath.equals(DataTypeDescriptions.categoryFromPath(path, name))) {
      return null;
    }
    if (expectedKind != null && DataTypeDescriptions.classifyKind(dataType) != expectedKind) {
      return null;
    }
    return path;
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
