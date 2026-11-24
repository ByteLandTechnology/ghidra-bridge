package app.byteland.ghidra.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.TransactionRunner;
import app.byteland.ghidra.service.address.AddressService;
import app.byteland.ghidra.service.analysis.AnalysisResource;
import app.byteland.ghidra.service.analysis.AnalysisService;
import app.byteland.ghidra.service.comment.CommentService;
import app.byteland.ghidra.service.datatype.DataTypeService;
import app.byteland.ghidra.service.decompilation.DecompilationService;
import app.byteland.ghidra.service.function.FunctionCallResource;
import app.byteland.ghidra.service.function.FunctionService;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService;
import app.byteland.ghidra.service.listing.ListingService;
import app.byteland.ghidra.service.memory.MemoryService;
import app.byteland.ghidra.service.program.ProgramService;
import app.byteland.ghidra.service.reference.ReferenceResource;
import app.byteland.ghidra.service.reference.ReferenceService;
import app.byteland.ghidra.service.symbol.SymbolService;
import java.lang.reflect.Proxy;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class ReferenceAndCallMethodsTest {
  @Test
  @SuppressWarnings("unchecked")
  void functionCallListPreservesCallSitesAndPaginatesWithSignedCursors() throws Exception {
    List<FunctionCallResource> allCallees =
        List.of(
            new FunctionCallResource(
                "ram:00401000",
                "helper",
                "ram:00402010",
                FunctionCallResource.Direction.CALLEES,
                "Global",
                null),
            new FunctionCallResource(
                "ram:00401000",
                "helper",
                "ram:00402028",
                FunctionCallResource.Direction.CALLEES,
                "Global",
                null));

    FunctionService functions =
        proxy(
            FunctionService.class,
            (method, args) -> {
              assertEquals("getCallees", method);
              int limit = (int) args[1];
              String cursor = (String) args[2];
              return Page.paginate(
                  allCallees,
                  limit,
                  cursor,
                  FunctionCallResource::entry,
                  FunctionCallResource::callSite);
            });

    ApiRegistry registry = registryWith(functions, unused(ReferenceService.class));

    Map<String, Object> pageOne =
        (Map<String, Object>)
            registry.dispatch(
                "function_call.list",
                Map.of(
                    "filter", Map.of("entry", "0x402000", "direction", "callees"),
                    "page", Map.of("limit", 1)));
    List<Map<String, Object>> itemsOne = (List<Map<String, Object>>) pageOne.get("items");
    assertEquals(1, itemsOne.size());
    assertEquals("ram:00401000", itemsOne.getFirst().get("entry"));
    assertEquals("ram:00402010", itemsOne.getFirst().get("call_site"));
    String cursor = (String) pageOne.get("next_cursor");
    assertNotNull(cursor);

    Map<String, Object> pageTwo =
        (Map<String, Object>)
            registry.dispatch(
                "function_call.list",
                Map.of(
                    "filter", Map.of("entry", "0x402000", "direction", "callees"),
                    "page", Map.of("limit", 1, "cursor", cursor)));
    List<Map<String, Object>> itemsTwo = (List<Map<String, Object>>) pageTwo.get("items");
    assertEquals(1, itemsTwo.size());
    assertEquals("ram:00401000", itemsTwo.getFirst().get("entry"));
    assertEquals("ram:00402028", itemsTwo.getFirst().get("call_site"));
    assertNull(pageTwo.get("next_cursor"));
  }

  @Test
  @SuppressWarnings("unchecked")
  void referenceListForwardsEntryAndFromRangeFiltersAndValidatesSchema() throws Exception {
    AtomicReference<List<Object>> recordedArgs = new AtomicReference<>();
    ReferenceService references =
        (fromRaw, entryRaw, fromRange, toRaw, type, direction, limit, cursor) -> {
          recordedArgs.set(
              Arrays.asList(fromRaw, entryRaw, fromRange, toRaw, type, direction, limit, cursor));
          return Page.of(
              List.of(
                  new ReferenceResource(
                      "ram:00401010", "ram:00401040", "CONDITIONAL_JUMP", 0, true, "DEFAULT")),
              limit,
              null);
        };

    ApiRegistry registry = registryWith(unused(FunctionService.class), references);

    Map<String, Object> byEntry =
        (Map<String, Object>)
            registry.dispatch(
                "reference.list",
                Map.of("filter", Map.of("direction", "from", "entry", "0x401000")));
    assertEquals(1, ((List<?>) byEntry.get("items")).size());
    assertEquals(
        Arrays.asList(null, "0x401000", null, null, null, "from", 100, null), recordedArgs.get());

    registry.dispatch(
        "reference.list",
        Map.of(
            "filter",
            Map.of(
                "direction",
                "from",
                "from_range",
                Map.of("start", "0x401000", "end", "0x401080"),
                "type",
                "CONDITIONAL_JUMP"),
            "page",
            Map.of("limit", 25)));
    assertEquals(
        Arrays.asList(
            null,
            null,
            new ReferenceService.RangeFilter("0x401000", "0x401080"),
            null,
            "CONDITIONAL_JUMP",
            "from",
            25,
            null),
        recordedArgs.get());

    assertThrows(
        ApiException.class,
        () ->
            registry.dispatch(
                "reference.list",
                Map.of(
                    "filter",
                    Map.of("direction", "from", "from_range", Map.of("start", "0x401000")))));
    assertThrows(
        ApiException.class,
        () ->
            registry.dispatch(
                "reference.list", Map.of("filter", Map.of("direction", "from", "entry", ""))));
  }

  private static ApiRegistry registryWith(FunctionService functions, ReferenceService references) {
    AnalysisService analysis =
        proxy(
            AnalysisService.class,
            (method, args) ->
                new AnalysisResource(
                    AnalysisResource.Kind.GHIDRA,
                    AnalysisResource.Status.IDLE,
                    false,
                    null,
                    null,
                    null,
                    null));
    TransactionRunner transaction =
        new TransactionRunner() {
          @Override
          public <T> T run(Operation<T> operation) {
            try {
              return operation.execute();
            } catch (Exception ex) {
              throw new RuntimeException(ex);
            }
          }
        };
    BridgeServices services =
        new BridgeServices(
            unused(ProgramService.class),
            unused(AddressService.class),
            unused(CommentService.class),
            references,
            unused(MemoryService.class),
            unused(ListingService.class),
            functions,
            unused(GlobalVariableService.class),
            analysis,
            unused(DecompilationService.class),
            unused(SymbolService.class),
            unused(DataTypeService.class),
            transaction,
            "test");
    return new ApiRegistry(services, "test", Map::of, () -> {});
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
