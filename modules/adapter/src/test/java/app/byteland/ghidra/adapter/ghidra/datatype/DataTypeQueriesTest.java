package app.byteland.ghidra.adapter.ghidra.datatype;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.adapter.ghidra.QuerySnapshotCache;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.datatype.DataTypeCategoryResource;
import app.byteland.ghidra.service.datatype.DataTypeResource;
import ghidra.app.script.GhidraScript;
import ghidra.framework.cmd.Command;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Program;
import java.lang.reflect.Proxy;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;

class DataTypeQueriesTest {

  @Test
  void boundedFirstPageSkipsSnapshotAndCursorSweepUsesSnapshotWithDeferredSummarize() {
    Fixture fixture = new Fixture(120);

    // Single-page call (cursor == null) uses bounded limit+1 selection, does NOT populate cache,
    // and calls summarize (getDescription) only on the 10 returned items.
    Page<DataTypeResource> firstPage =
        DataTypeQueries.searchDataTypes(
            fixture.session, fixture.manager, "", null, null, 10, null);
    assertEquals(10, firstPage.items().size());
    assertEquals("/pkg/Type_0000", firstPage.items().getFirst().path());
    assertEquals("/pkg/Type_0009", firstPage.nextCursor());
    assertEquals(0, fixture.cache.entryCount(), "cursor == null must not populate snapshot cache");
    assertEquals(1, fixture.fullScans.get());
    assertEquals(10, fixture.summarizeCalls.get(), "zero discarded DataTypeResource summaries");

    // Second page (first cursor call) populates 1 snapshot; pages 3..12 hit the cached snapshot
    // without calling getAllDataTypes() again!
    List<String> warmSweepPaths = new ArrayList<>();
    warmSweepPaths.addAll(firstPage.items().stream().map(DataTypeResource::path).toList());
    String cursor = firstPage.nextCursor();
    while (cursor != null) {
      Page<DataTypeResource> page =
          DataTypeQueries.searchDataTypes(
              fixture.session, fixture.manager, "", null, null, 10, cursor);
      warmSweepPaths.addAll(page.items().stream().map(DataTypeResource::path).toList());
      cursor = page.nextCursor();
    }

    assertEquals(120, warmSweepPaths.size());
    assertEquals(1, fixture.cache.entryCount());
    assertEquals(2, fixture.fullScans.get(), "only page 1 and page 2 scanned getAllDataTypes()");
    assertEquals(120, fixture.summarizeCalls.get(), "each of 120 types summarized once total");

    // Verify identical items, sort order, and cursors across:
    // (a) TTL expiry between pages, (b) LRU eviction, and (c) analysis bypass!
    List<String> ttlExpiredSweep = sweepWithMode(fixture, SweepMode.EXPIRE_TTL_EACH_PAGE);
    List<String> evictedSweep = sweepWithMode(fixture, SweepMode.CLEAR_CACHE_EACH_PAGE);
    List<String> analyzingSweep = sweepWithMode(fixture, SweepMode.ANALYZING_BYPASS);

    assertEquals(warmSweepPaths, ttlExpiredSweep);
    assertEquals(warmSweepPaths, evictedSweep);
    assertEquals(warmSweepPaths, analyzingSweep);
  }

  @Test
  void invalidatesOnModificationNumberChangeTransactionsAndClose() {
    Fixture fixture = new Fixture(15);

    Page<DataTypeResource> p1 =
        DataTypeQueries.searchDataTypes(
            fixture.session, fixture.manager, "", null, "struct", 5, null);
    Page<DataTypeResource> p2 =
        DataTypeQueries.searchDataTypes(
            fixture.session, fixture.manager, "", null, "STRUCT", 5, p1.nextCursor());
    assertEquals(5, p2.items().size());
    assertEquals(1, fixture.cache.entryCount());

    // External GUI mutation increments Program.getModificationNumber() and adds Type_0006_ext.
    fixture.addType("/pkg/Type_0006_ext");
    fixture.modificationNumber.incrementAndGet();

    Page<DataTypeResource> p2AfterGuiEdit =
        DataTypeQueries.searchDataTypes(
            fixture.session, fixture.manager, "", null, "struct", 5, p1.nextCursor());
    assertEquals("/pkg/Type_0006_ext", p2AfterGuiEdit.items().get(2).path());

    // GhidraSession transaction evicts cached snapshots.
    assertEquals(1, fixture.cache.entryCount());
    fixture.session.withTransaction(() -> "mutated");
    assertEquals(0, fixture.cache.entryCount());

    // Re-populate and verify runCommand and close() also clear cached snapshots.
    DataTypeQueries.searchDataTypes(
        fixture.session, fixture.manager, "", null, "struct", 5, p1.nextCursor());
    assertEquals(1, fixture.cache.entryCount());
    fixture.session.runCommand(
        new Command<>() {
          @Override
          public boolean applyTo(Program obj) {
            return true;
          }

          @Override
          public String getStatusMsg() {
            return "ok";
          }

          @Override
          public String getName() {
            return "noop";
          }
        },
        "failed");
    assertEquals(0, fixture.cache.entryCount());

    DataTypeQueries.searchDataTypes(
        fixture.session, fixture.manager, "", null, "struct", 5, p1.nextCursor());
    assertEquals(1, fixture.cache.entryCount());
    fixture.session.close();
    assertEquals(0, fixture.cache.entryCount());
  }

  @Test
  void listCategoriesUsesBoundedFirstPageAndCachesSortedCategoryKeys() {
    Fixture fixture = new Fixture(10);
    fixture.addCategories(25);

    Page<DataTypeCategoryResource> first =
        DataTypeQueries.listCategories(fixture.session, fixture.manager, "/", 6, null);
    assertEquals(6, first.items().size());
    assertEquals("/cat_00", first.items().getFirst().path());
    assertEquals("/cat_05", first.nextCursor());
    assertEquals(0, fixture.cache.entryCount());
    assertEquals(6, fixture.categoryDetailCalls.get());

    Page<DataTypeCategoryResource> second =
        DataTypeQueries.listCategories(
            fixture.session, fixture.manager, "/", 6, first.nextCursor());
    assertEquals(6, second.items().size());
    assertEquals("/cat_06", second.items().getFirst().path());
    assertEquals(1, fixture.cache.entryCount());

    int scansAfterSecond = fixture.categoryListScans.get();
    Page<DataTypeCategoryResource> third =
        DataTypeQueries.listCategories(
            fixture.session, fixture.manager, "/", 6, second.nextCursor());
    assertEquals(6, third.items().size());
    assertEquals("/cat_12", third.items().getFirst().path());
    assertEquals(scansAfterSecond, fixture.categoryListScans.get(), "third page hits snapshot");

    // Non-matching kind filter short-circuits cleanly.
    Page<DataTypeResource> unknownKind =
        DataTypeQueries.searchDataTypes(
            fixture.session, fixture.manager, "", null, "not_a_kind", 10, null);
    assertEquals(List.of(), unknownKind.items());
    assertNull(unknownKind.nextCursor());
  }

  private enum SweepMode {
    EXPIRE_TTL_EACH_PAGE,
    CLEAR_CACHE_EACH_PAGE,
    ANALYZING_BYPASS
  }

  private static List<String> sweepWithMode(Fixture fixture, SweepMode mode) {
    fixture.cache.clear();
    fixture.analyzing.set(mode == SweepMode.ANALYZING_BYPASS);
    try {
      List<String> collected = new ArrayList<>();
      String cursor = null;
      while (true) {
        if (mode == SweepMode.EXPIRE_TTL_EACH_PAGE) {
          fixture.clockNanos.addAndGet(Duration.ofSeconds(31).toNanos());
        } else if (mode == SweepMode.CLEAR_CACHE_EACH_PAGE) {
          fixture.cache.clear();
        }
        Page<DataTypeResource> page =
            DataTypeQueries.searchDataTypes(
                fixture.session, fixture.manager, "", null, null, 10, cursor);
        if (mode == SweepMode.ANALYZING_BYPASS) {
          assertEquals(0, fixture.cache.entryCount(), "analyzing must bypass cache storage");
        }
        collected.addAll(page.items().stream().map(DataTypeResource::path).toList());
        cursor = page.nextCursor();
        if (cursor == null) {
          break;
        }
      }
      return collected;
    } finally {
      fixture.analyzing.set(false);
    }
  }

  private static final class Fixture {
    final AtomicLong clockNanos = new AtomicLong(1_000_000L);
    final AtomicLong modificationNumber = new AtomicLong(1L);
    final AtomicBoolean analyzing = new AtomicBoolean(false);
    final AtomicInteger fullScans = new AtomicInteger();
    final AtomicInteger summarizeCalls = new AtomicInteger();
    final AtomicInteger categoryListScans = new AtomicInteger();
    final AtomicInteger categoryDetailCalls = new AtomicInteger();

    final Map<String, DataType> typesByPath = new LinkedHashMap<>();
    final List<DataType> unorderedTypes = new ArrayList<>();
    final Map<String, Category> categoriesByPath = new LinkedHashMap<>();
    final List<Category> childCategories = new ArrayList<>();

    final QuerySnapshotCache cache =
        new QuerySnapshotCache(16, 10_000, Duration.ofSeconds(30), clockNanos::get);
    final DataTypeManager manager;
    final Program program;
    final GhidraSession session;

    Fixture(int count) {
      for (int i = 0; i < count; i++) {
        addType(String.format("/pkg/Type_%04d", i));
      }
      Collections.shuffle(unorderedTypes, new Random(7L));

      Category rootCategory =
          (Category)
              Proxy.newProxyInstance(
                  Category.class.getClassLoader(),
                  new Class<?>[] {Category.class},
                  (proxy, method, args) ->
                      switch (method.getName()) {
                        case "getCategoryPath" -> CategoryPath.ROOT;
                        case "getName" -> "";
                        case "getCategories" -> {
                          categoryListScans.incrementAndGet();
                          yield childCategories.toArray(Category[]::new);
                        }
                        case "getDataTypes" -> new DataType[0];
                        default -> throw new UnsupportedOperationException(method.getName());
                      });
      categoriesByPath.put("/", rootCategory);

      this.manager =
          (DataTypeManager)
              Proxy.newProxyInstance(
                  DataTypeManager.class.getClassLoader(),
                  new Class<?>[] {DataTypeManager.class},
                  (proxy, method, args) ->
                      switch (method.getName()) {
                        case "getAllDataTypes" -> {
                          fullScans.incrementAndGet();
                          yield unorderedTypes.iterator();
                        }
                        case "getDataType" -> typesByPath.get((String) args[0]);
                        case "getCategory" ->
                            categoriesByPath.get(((CategoryPath) args[0]).getPath());
                        default -> throw new UnsupportedOperationException(method.getName());
                      });

      this.program =
          (Program)
              Proxy.newProxyInstance(
                  Program.class.getClassLoader(),
                  new Class<?>[] {Program.class},
                  (proxy, method, args) ->
                      switch (method.getName()) {
                        case "getModificationNumber" -> modificationNumber.get();
                        case "getDataTypeManager" -> manager;
                        case "startTransaction" -> 1;
                        case "endTransaction" -> true;
                        default -> throw new UnsupportedOperationException(method.getName());
                      });

      GhidraScript script =
          new GhidraScript() {
            {
              this.currentProgram = program;
            }

            @Override
            protected void run() {}
          };
      this.session = new GhidraSession(script, cache, analyzing::get);
    }

    void addType(String path) {
      int slash = path.lastIndexOf('/');
      String name = path.substring(slash + 1);
      CategoryPath catPath = new CategoryPath(slash <= 0 ? "/" : path.substring(0, slash));
      DataType type =
          (DataType)
              Proxy.newProxyInstance(
                  Structure.class.getClassLoader(),
                  new Class<?>[] {Structure.class},
                  (proxy, method, args) ->
                      switch (method.getName()) {
                        case "getPathName" -> path;
                        case "getName" -> name;
                        case "getCategoryPath" -> catPath;
                        case "getLength" -> 16;
                        case "getDescription" -> {
                          summarizeCalls.incrementAndGet();
                          yield "struct " + name;
                        }
                        default -> throw new UnsupportedOperationException(method.getName());
                      });
      typesByPath.put(path, type);
      unorderedTypes.add(type);
    }

    void addCategories(int count) {
      for (int i = count - 1; i >= 0; i--) {
        String path = String.format("/cat_%02d", i);
        String name = String.format("cat_%02d", i);
        CategoryPath cp = new CategoryPath(path);
        Category cat =
            (Category)
                Proxy.newProxyInstance(
                    Category.class.getClassLoader(),
                    new Class<?>[] {Category.class},
                    (proxy, method, args) ->
                        switch (method.getName()) {
                          case "getCategoryPath" -> cp;
                          case "getName" -> name;
                          case "getCategories" -> new Category[0];
                          case "getDataTypes" -> {
                            categoryDetailCalls.incrementAndGet();
                            yield new DataType[0];
                          }
                          default -> throw new UnsupportedOperationException(method.getName());
                        });
        categoriesByPath.put(path, cat);
        childCategories.add(cat);
      }
    }
  }
}
