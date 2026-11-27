package app.byteland.ghidra.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.ScanProgress;
import app.byteland.ghidra.service.TransactionRunner;
import app.byteland.ghidra.service.address.AddressService;
import app.byteland.ghidra.service.analysis.AnalysisService;
import app.byteland.ghidra.service.comment.CommentService;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.datatype.DataTypeService;
import app.byteland.ghidra.service.decompilation.DecompilationService;
import app.byteland.ghidra.service.function.FunctionService;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService;
import app.byteland.ghidra.service.listing.DataUnitResource;
import app.byteland.ghidra.service.listing.ListingService;
import app.byteland.ghidra.service.listing.StringResource;
import app.byteland.ghidra.service.memory.MemoryMatchResource;
import app.byteland.ghidra.service.memory.MemoryService;
import app.byteland.ghidra.service.program.ProgramService;
import app.byteland.ghidra.service.reference.ReferenceService;
import app.byteland.ghidra.service.symbol.SymbolService;
import java.lang.reflect.Proxy;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class SearchMethodsWireTest {
  @Test
  @SuppressWarnings("unchecked")
  void dispatchesStringListMemoryFindAndPreservesDataUnitList() throws Exception {
    AtomicReference<ListingService.StringQuery> capturedStringQuery = new AtomicReference<>();
    AtomicReference<MemoryService.MemoryFindQuery> capturedMemoryQuery = new AtomicReference<>();

    ScanProgress progress =
        new ScanProgress(
            ScanProgress.Kind.ADDRESS,
            "ram:00100000",
            "ram:00101000",
            "ram:00100000",
            "ram:00100020",
            false,
            ScanProgress.StopReason.LIMIT,
            3L);

    ListingService listing =
        proxy(
            ListingService.class,
            (method, args) -> {
              if ("listStrings".equals(method)) {
                ListingService.StringQuery query = (ListingService.StringQuery) args[0];
                capturedStringQuery.set(query);
                return Page.scanned(
                    List.of(
                        new StringResource(
                            "ram:00100010",
                            6,
                            "hello",
                            "US-ASCII",
                            true,
                            DataTypeReference.named("string"))),
                    query.limit(),
                    "ram:00100015",
                    progress);
              }
              if ("listDataUnits".equals(method)) {
                return Page.scanned(
                    List.of(
                        new DataUnitResource(
                            "ram:00100000",
                            4,
                            DataTypeReference.named("uint"),
                            "42",
                            "2ah",
                            new ByteSequence(ByteSequence.Encoding.HEX, "2a000000", 4))),
                    50,
                    null,
                    new ScanProgress(
                        ScanProgress.Kind.ADDRESS,
                        "ram:00100000",
                        "ram:00100003",
                        "ram:00100000",
                        "ram:00100003",
                        true,
                        ScanProgress.StopReason.COMPLETED,
                        1L));
              }
              throw new AssertionError(method);
            });

    MemoryService memory =
        proxy(
            MemoryService.class,
            (method, args) -> {
              assertEquals("findMemory", method);
              MemoryService.MemoryFindQuery query = (MemoryService.MemoryFindQuery) args[0];
              capturedMemoryQuery.set(query);
              return Page.scanned(
                  List.of(
                      new MemoryMatchResource(
                          "ram:00100020",
                          4,
                          new ByteSequence(ByteSequence.Encoding.HEX, "488b0510", 4))),
                  query.limit(),
                  "ram:00100020",
                  progress);
            });

    TransactionRunner noTransactions =
        new TransactionRunner() {
          @Override
          public <T> T run(Operation<T> operation) {
            throw new AssertionError("read-only search must not start a transaction");
          }
        };

    BridgeServices services =
        new BridgeServices(
            unused(ProgramService.class),
            unused(AddressService.class),
            unused(CommentService.class),
            unused(ReferenceService.class),
            memory,
            listing,
            unused(FunctionService.class),
            unused(GlobalVariableService.class),
            unused(AnalysisService.class),
            unused(DecompilationService.class),
            unused(SymbolService.class),
            unused(DataTypeService.class),
            noTransactions,
            "test");
    ApiRegistry registry = new ApiRegistry(services, "test", Map::of, () -> {});

    Map<String, Object> iface = (Map<String, Object>) registry.dispatch("interface.get", Map.of());
    List<Map<String, Object>> methods = (List<Map<String, Object>>) iface.get("methods");
    assertEquals(58, methods.size());
    assertTrue(methods.stream().anyMatch(m -> "string.list".equals(m.get("name"))));
    assertTrue(methods.stream().anyMatch(m -> "memory.find".equals(m.get("name"))));

    Map<String, Object> stringResult =
        (Map<String, Object>)
            registry.dispatch(
                "string.list",
                Map.of(
                    "scan",
                    Map.of("range", Map.of("start", "0x100000", "end", "0x101000"), "timeout_ms", 500),
                    "filter",
                    Map.of(
                        "query",
                        "hel",
                        "regex",
                        "^hel",
                        "case_sensitive",
                        true,
                        "min_length",
                        4,
                        "encoding",
                        "ASCII",
                        "include_candidates",
                        true),
                    "page",
                    Map.of("limit", 10)));
    ListingService.StringQuery sq = capturedStringQuery.get();
    assertEquals("0x100000", sq.scan().start());
    assertEquals("0x101000", sq.scan().end());
    assertEquals(500, sq.scan().timeoutMs());
    assertEquals("hel", sq.query());
    assertEquals("^hel", sq.regex());
    assertTrue(sq.caseSensitive());
    assertEquals(4, sq.minLength());
    assertEquals("ASCII", sq.encoding());
    assertTrue(sq.includeCandidates());
    assertEquals(10, sq.limit());

    List<Map<String, Object>> stringItems = (List<Map<String, Object>>) stringResult.get("items");
    assertEquals(1, stringItems.size());
    Map<String, Object> firstString = stringItems.get(0);
    assertEquals("ram:00100010", firstString.get("address"));
    assertEquals("hello", firstString.get("value"));
    assertEquals("US-ASCII", firstString.get("encoding"));
    assertEquals(true, firstString.get("defined"));
    assertFalse(firstString.containsKey("bytes"));
    assertNotNull(stringResult.get("next_cursor"));

    Map<String, Object> defaultStringPage =
        (Map<String, Object>) registry.dispatch("string.list", Map.of());
    String defaultStringCursor = (String) defaultStringPage.get("next_cursor");
    assertNotNull(defaultStringCursor);
    registry.dispatch(
        "string.list",
        Map.of(
            "filter", Map.of("case_sensitive", false, "include_candidates", false),
            "page", Map.of("limit", 100, "cursor", defaultStringCursor),
            "scan", Map.of("range", Map.of(), "timeout_ms", 1000)));
    assertEquals("ram:00100015", capturedStringQuery.get().cursor());

    Map<String, Object> findResult =
        (Map<String, Object>)
            registry.dispatch(
                "memory.find",
                Map.of(
                    "filter", Map.of("pattern", "48 8B ?? 10"),
                    "page", Map.of("limit", 5)));
    assertEquals("48 8B ?? 10", capturedMemoryQuery.get().pattern());
    List<Map<String, Object>> matchItems = (List<Map<String, Object>>) findResult.get("items");
    assertEquals(1, matchItems.size());
    assertEquals("ram:00100020", matchItems.get(0).get("address"));
    assertEquals(
        Map.of("encoding", "hex", "data", "488b0510", "length", 4),
        matchItems.get(0).get("bytes"));
    assertNotNull(findResult.get("next_cursor"));

    Map<String, Object> projectedStrings =
        (Map<String, Object>)
            registry.dispatch(
                "string.list",
                Map.of("projection", Map.of("fields", List.of("value", "defined"))));
    List<Map<String, Object>> projectedStringItems =
        (List<Map<String, Object>>) projectedStrings.get("items");
    assertEquals(
        List.of(Map.of("address", "ram:00100010", "value", "hello", "defined", true)),
        projectedStringItems);

    Map<String, Object> projectedMatches =
        (Map<String, Object>)
            registry.dispatch(
                "memory.find",
                Map.of(
                    "filter", Map.of("pattern", "48 8B ?? 10"),
                    "projection", Map.of("fields", List.of("length"))));
    List<Map<String, Object>> projectedMatchItems =
        (List<Map<String, Object>>) projectedMatches.get("items");
    assertEquals(List.of(Map.of("address", "ram:00100020", "length", 4)), projectedMatchItems);

    var missingFilter =
        ApiFailures.normalize(
            assertThrows(Exception.class, () -> registry.dispatch("memory.find", Map.of())));
    assertEquals(400, missingFilter.status());
    assertNotNull(missingFilter.error().code());

    var blankPattern =
        ApiFailures.normalize(
            assertThrows(
                Exception.class,
                () -> registry.dispatch("memory.find", Map.of("filter", Map.of("pattern", "   ")))));
    assertEquals(400, blankPattern.status());
    assertEquals("invalid_request", blankPattern.error().code());

    var zeroMinLength =
        ApiFailures.normalize(
            assertThrows(
                Exception.class,
                () -> registry.dispatch("string.list", Map.of("filter", Map.of("min_length", 0)))));
    assertEquals(400, zeroMinLength.status());
    assertNotNull(zeroMinLength.error().code());

    Map<String, Object> dataUnits =
        (Map<String, Object>) registry.dispatch("data_unit.list", Map.of());
    List<Map<String, Object>> dataUnitItems = (List<Map<String, Object>>) dataUnits.get("items");
    assertEquals(
        Map.of("encoding", "hex", "data", "2a000000", "length", 4),
        dataUnitItems.get(0).get("bytes"));
    assertEquals("2ah", dataUnitItems.get(0).get("representation"));
  }

  private interface Handler {
    Object invoke(String method, Object[] args);
  }

  private static <T> T unused(Class<T> type) {
    return proxy(
        type,
        (method, args) -> {
          throw new AssertionError(method);
        });
  }

  private static <T> T proxy(Class<T> type, Handler handler) {
    return type.cast(
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (proxy, method, args) -> handler.invoke(method.getName(), args)));
  }
}
