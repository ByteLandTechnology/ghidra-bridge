package app.byteland.ghidra.adapter.ghidra.datatype;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.datatype.DataTypeCategoryResource;
import app.byteland.ghidra.service.datatype.DataTypeResource;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class DataTypeQueriesTest {

  @Test
  void listCategoriesSelectsChildPathsBeforeReadingCountsAndSupportsCursor() {
    Set<String> allowedCountReads = Set.of("/alpha", "/beta");
    Category delta = childCategory("/delta", "delta", 4, 8, allowedCountReads);
    Category beta = childCategory("/beta", "beta", 2, 5, allowedCountReads);
    Category alpha = childCategory("/alpha", "alpha", 1, 3, allowedCountReads);
    Category gamma = childCategory("/gamma", "gamma", 7, 9, allowedCountReads);
    Category root = parentCategory("/", new Category[] {delta, beta, alpha, gamma}, null);
    DataTypeManager manager =
        managerWithCategories(Map.of(CategoryPath.ROOT, root), List.of(), null);

    Page<DataTypeCategoryResource> first = DataTypeQueries.listCategories(manager, "/", 2, null);
    assertEquals(
        List.of(
            new DataTypeCategoryResource("/alpha", "alpha", 1, 3),
            new DataTypeCategoryResource("/beta", "beta", 2, 5)),
        first.items());
    assertEquals("/beta", first.nextCursor());

    Set<String> secondAllowed = Set.of("/delta", "/gamma");
    Category rootSecond =
        parentCategory(
            "/",
            new Category[] {
              childCategory("/delta", "delta", 4, 8, secondAllowed),
              childCategory("/beta", "beta", 2, 5, secondAllowed),
              childCategory("/alpha", "alpha", 1, 3, secondAllowed),
              childCategory("/gamma", "gamma", 7, 9, secondAllowed)
            },
            null);
    DataTypeManager secondManager =
        managerWithCategories(Map.of(CategoryPath.ROOT, rootSecond), List.of(), null);

    Page<DataTypeCategoryResource> second =
        DataTypeQueries.listCategories(secondManager, null, 2, first.nextCursor());
    assertEquals(
        List.of(
            new DataTypeCategoryResource("/delta", "delta", 4, 8),
            new DataTypeCategoryResource("/gamma", "gamma", 7, 9)),
        second.items());
    assertNull(second.nextCursor());

    assertThrows(
        NoSuchElementException.class,
        () -> DataTypeQueries.listCategories(manager, "/missing", 10, null));
  }

  @Test
  void searchDataTypesScopesToCategoryAndReturnsEmptyForInvalidOrMissingCategory() {
    AtomicBoolean scannedAll = new AtomicBoolean(false);
    AtomicInteger summarized = new AtomicInteger();

    DataType structB = mockType(Structure.class, "/net/PacketB", "PacketB", 16, "b", summarized);
    DataType enumSkip =
        mockType(ghidra.program.model.data.Enum.class, "/net/State", "State", 4, "s", summarized);
    DataType structA = mockType(Structure.class, "/net/PacketA", "PacketA", 8, "a", summarized);
    DataType structC = mockType(Structure.class, "/net/PacketC", "PacketC", 32, "c", summarized);

    Category netCategory =
        parentCategory(
            "/net", new Category[0], new DataType[] {structB, enumSkip, structC, structA});
    Map<CategoryPath, Category> categories = new HashMap<>();
    categories.put(new CategoryPath("/net"), netCategory);
    DataTypeManager manager = managerWithCategories(categories, List.of(), scannedAll);

    Page<DataTypeResource> page1 =
        DataTypeQueries.searchDataTypes(manager, "packet", "/net", "struct", 2, null);
    assertEquals(
        List.of("/net/PacketA", "/net/PacketB"),
        page1.items().stream().map(DataTypeResource::path).toList());
    assertEquals("/net/PacketB", page1.nextCursor());
    assertEquals(2, summarized.get());
    assertTrue(!scannedAll.get());

    Page<DataTypeResource> page2 =
        DataTypeQueries.searchDataTypes(manager, "packet", "/net", "struct", 2, page1.nextCursor());
    assertEquals(
        List.of("/net/PacketC"), page2.items().stream().map(DataTypeResource::path).toList());
    assertNull(page2.nextCursor());
    assertEquals(3, summarized.get());

    for (String badOrMissing : List.of("", "net", "/net/", "/a//b", "/missing")) {
      Page<DataTypeResource> empty =
          DataTypeQueries.searchDataTypes(manager, "", badOrMissing, null, 10, null);
      assertTrue(empty.items().isEmpty(), "expected empty page for " + badOrMissing);
      assertNull(empty.nextCursor());
    }
    Page<DataTypeResource> unknownKind =
        DataTypeQueries.searchDataTypes(manager, "", "/net", "unknown_kind", 10, null);
    assertTrue(unknownKind.items().isEmpty());
    assertEquals(3, summarized.get());
    assertTrue(!scannedAll.get());
  }

  @Test
  void searchDataTypesPaginatesAllCategoriesWithZeroDiscardedSummaries() {
    AtomicInteger summarized = new AtomicInteger();
    List<DataType> allTypes = new ArrayList<>();
    for (int index = 25; index >= 1; index--) {
      String name = String.format("Type_%02d", index);
      allTypes.add(mockType(Structure.class, "/types/" + name, name, index * 4, "doc", summarized));
    }
    DataTypeManager manager = managerWithCategories(Map.of(), allTypes, null);

    List<String> collected = new ArrayList<>();
    String cursor = null;
    while (true) {
      Page<DataTypeResource> page =
          DataTypeQueries.searchDataTypes(manager, "", null, "STRUCT", 7, cursor);
      collected.addAll(page.items().stream().map(DataTypeResource::name).toList());
      cursor = page.nextCursor();
      if (cursor == null) break;
    }

    assertEquals(25, collected.size());
    assertEquals("Type_01", collected.getFirst());
    assertEquals("Type_25", collected.getLast());
    assertEquals(25, summarized.get());
  }

  private static Category childCategory(
      String path, String name, int subCount, int typeCount, Set<String> allowedCountReads) {
    CategoryPath categoryPath = new CategoryPath(path);
    return (Category)
        Proxy.newProxyInstance(
            Category.class.getClassLoader(),
            new Class<?>[] {Category.class},
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "getCategoryPath" -> categoryPath;
                  case "getName" -> name;
                  case "getCategories" -> {
                    if (!allowedCountReads.contains(path)) {
                      throw new AssertionError("unexpected getCategories on " + path);
                    }
                    yield new Category[subCount];
                  }
                  case "getDataTypes" -> {
                    if (!allowedCountReads.contains(path)) {
                      throw new AssertionError("unexpected getDataTypes on " + path);
                    }
                    yield new DataType[typeCount];
                  }
                  default -> throw new AssertionError(method.getName());
                });
  }

  private static Category parentCategory(String path, Category[] children, DataType[] types) {
    CategoryPath categoryPath = new CategoryPath(path);
    return (Category)
        Proxy.newProxyInstance(
            Category.class.getClassLoader(),
            new Class<?>[] {Category.class},
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "getCategoryPath" -> categoryPath;
                  case "getName" -> categoryPath.getName();
                  case "getCategories" -> children;
                  case "getDataTypes" -> types;
                  default -> throw new AssertionError(method.getName());
                });
  }

  private static DataType mockType(
      Class<? extends DataType> typeInterface,
      String path,
      String name,
      int length,
      String description,
      AtomicInteger summarized) {
    return (DataType)
        Proxy.newProxyInstance(
            DataType.class.getClassLoader(),
            new Class<?>[] {typeInterface},
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "getName" -> name;
                  case "getPathName" -> path;
                  case "getLength" -> length;
                  case "getDescription" -> {
                    summarized.incrementAndGet();
                    yield description;
                  }
                  default -> throw new AssertionError(method.getName());
                });
  }

  private static DataTypeManager managerWithCategories(
      Map<CategoryPath, Category> categories,
      List<DataType> allDataTypes,
      AtomicBoolean scannedAll) {
    return (DataTypeManager)
        Proxy.newProxyInstance(
            DataTypeManager.class.getClassLoader(),
            new Class<?>[] {DataTypeManager.class},
            (proxy, method, args) ->
                switch (method.getName()) {
                  case "getCategory" -> categories.get((CategoryPath) args[0]);
                  case "getAllDataTypes" -> {
                    if (scannedAll != null) scannedAll.set(true);
                    yield allDataTypes.iterator();
                  }
                  default -> throw new AssertionError(method.getName());
                });
  }
}
