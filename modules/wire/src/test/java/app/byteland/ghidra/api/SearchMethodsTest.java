package app.byteland.ghidra.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.ScanProgress;
import app.byteland.ghidra.service.TransactionRunner;
import app.byteland.ghidra.service.address.AddressService;
import app.byteland.ghidra.service.analysis.AnalysisResource;
import app.byteland.ghidra.service.analysis.AnalysisService;
import app.byteland.ghidra.service.comment.CommentService;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.datatype.DataTypeService;
import app.byteland.ghidra.service.decompilation.DecompilationService;
import app.byteland.ghidra.service.function.FunctionService;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService;
import app.byteland.ghidra.service.listing.ListingService;
import app.byteland.ghidra.service.memory.MemoryService;
import app.byteland.ghidra.service.program.ProgramService;
import app.byteland.ghidra.service.reference.ReferenceService;
import app.byteland.ghidra.service.search.BytePatternMatchesResource;
import app.byteland.ghidra.service.search.ByteSearchResult;
import app.byteland.ghidra.service.search.SearchService;
import app.byteland.ghidra.service.search.StringMatchResource;
import app.byteland.ghidra.service.search.StringSearchResult;
import app.byteland.ghidra.service.symbol.SymbolService;
import java.lang.reflect.Proxy;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class SearchMethodsTest {

  @Test
  @SuppressWarnings("unchecked")
  void dispatchesSearchStringsAndSearchBytesWithProjectionCursorsAndValidation() throws Exception {
    List<StringMatchResource> fixtures =
        List.of(
            new StringMatchResource(
                "ram:00401000",
                "alpha_key",
                10,
                StringMatchResource.Encoding.ASCII,
                true,
                DataTypeReference.named("string")),
            new StringMatchResource(
                "ram:00401020",
                "beta_wide",
                18,
                StringMatchResource.Encoding.UTF16LE,
                false,
                null));

    SearchService searchService =
        new SearchService() {
          @Override
          public StringSearchResult searchStrings(StringSearchQuery query) {
            Page<StringMatchResource> page =
                Page.paginate(fixtures, query.limit(), query.cursor(), StringMatchResource::address);
            return new StringSearchResult(page, true, fixtures.size(), 42L);
          }

          @Override
          public ByteSearchResult searchBytes(ByteSearchQuery query) {
            if (query.cursor() == null) {
              return new ByteSearchResult(
                  List.of(
                      new BytePatternMatchesResource(
                          0, query.patterns().getFirst(), List.of("ram:00401000"), 1)),
                  1,
                  "ram:00401000@0",
                  new ScanProgress(
                      ScanProgress.Kind.ADDRESS,
                      "ram:00401000",
                      "ram:00402000",
                      "ram:00401000",
                      "ram:00401000",
                      false,
                      ScanProgress.StopReason.LIMIT,
                      3L));
            }
            assertEquals("ram:00401000@0", query.cursor());
            return new ByteSearchResult(
                List.of(
                    new BytePatternMatchesResource(
                        0, query.patterns().getFirst(), List.of("ram:00401100"), 1)),
                1,
                null,
                new ScanProgress(
                    ScanProgress.Kind.ADDRESS,
                    "ram:00401000",
                    "ram:00402000",
                    "ram:00401001",
                    "ram:00402000",
                    true,
                    ScanProgress.StopReason.COMPLETED,
                    2L));
          }
        };

    ApiRegistry registry = new ApiRegistry(stubServices(searchService), "sess-search", Map::of, () -> {});

    Map<String, Object> page1 =
        (Map<String, Object>)
            registry.dispatch(
                "search.strings",
                Map.of(
                    "page", Map.of("limit", 1),
                    "projection", Map.of("fields", List.of("value", "encoding"))));
    assertEquals(true, page1.get("index_complete"));
    assertEquals(2, page1.get("total_indexed"));
    assertEquals(42L, page1.get("modification_number"));
    List<Map<String, Object>> items1 = (List<Map<String, Object>>) page1.get("items");
    assertEquals(1, items1.size());
    assertEquals(
        Map.of("address", "ram:00401000", "value", "alpha_key", "encoding", "ascii"),
        items1.getFirst());
    assertFalse(items1.getFirst().containsKey("bytes"));

    String cursor = (String) page1.get("next_cursor");
    Map<String, Object> page2 =
        (Map<String, Object>)
            registry.dispatch("search.strings", Map.of("page", Map.of("limit", 1, "cursor", cursor)));
    List<Map<String, Object>> items2 = (List<Map<String, Object>>) page2.get("items");
    assertEquals("beta_wide", items2.getFirst().get("value"));
    assertFalse(page2.containsKey("next_cursor"));

    ApiException badRegex =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "search.strings", Map.of("filter", Map.of("regex", "[unclosed"))));
    assertEquals(400, badRegex.status());
    assertEquals("invalid_regex", badRegex.error().code());
    assertEquals("/filter/regex", badRegex.error().target());

    Map<String, Object> bytesPage1 =
        (Map<String, Object>)
            registry.dispatch(
                "search.bytes",
                Map.of("patterns", List.of("48 89 ??"), "page", Map.of("limit", 1)));
    assertEquals(1, bytesPage1.get("total_matches"));
    assertTrue(bytesPage1.containsKey("next_cursor"));

    Map<String, Object> bytesPage2 =
        (Map<String, Object>)
            registry.dispatch(
                "search.bytes",
                Map.of(
                    "patterns",
                    List.of("48 89 ??"),
                    "page",
                    Map.of("limit", 1, "cursor", bytesPage1.get("next_cursor"))));
    assertEquals(1, bytesPage2.get("total_matches"));
    assertFalse(bytesPage2.containsKey("next_cursor"));

    ApiException badPattern =
        assertThrows(
            ApiException.class,
            () -> registry.dispatch("search.bytes", Map.of("patterns", List.of("48 ZZ"))));
    assertEquals(400, badPattern.status());
    assertEquals("invalid_pattern", badPattern.error().code());
    assertEquals("/patterns/0", badPattern.error().target());
  }

  private static BridgeServices stubServices(SearchService searchService) {
    AnalysisService analysis =
        new AnalysisService() {
          @Override
          public AnalysisResource startAnalysis(List<String> analyzers) {
            throw new UnsupportedOperationException();
          }

          @Override
          public AnalysisResource getStatus() {
            return new AnalysisResource(
                AnalysisResource.Kind.BRIDGE,
                AnalysisResource.Status.IDLE,
                true,
                null,
                null,
                null,
                null);
          }

          @Override
          public void close() {}
        };
    return new BridgeServices(
        unused(ProgramService.class),
        unused(AddressService.class),
        unused(CommentService.class),
        unused(ReferenceService.class),
        unused(MemoryService.class),
        unused(ListingService.class),
        unused(FunctionService.class),
        unused(GlobalVariableService.class),
        analysis,
        unused(DecompilationService.class),
        unused(SymbolService.class),
        unused(DataTypeService.class),
        searchService,
        new TransactionRunner() {
          @Override
          public <T> T run(Operation<T> operation) {
            try {
              return operation.execute();
            } catch (Exception ex) {
              throw new RuntimeException(ex);
            }
          }
        },
        "test-prog");
  }

  private static <T> T unused(Class<T> type) {
    return type.cast(
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (proxy, method, args) -> {
              if ("close".equals(method.getName())) return null;
              throw new AssertionError("unexpected call: " + method.getName());
            }));
  }
}
