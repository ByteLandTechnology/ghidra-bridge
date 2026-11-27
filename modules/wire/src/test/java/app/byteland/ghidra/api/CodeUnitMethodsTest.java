package app.byteland.ghidra.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.Page;
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
import app.byteland.ghidra.service.listing.CodeUnitResource;
import app.byteland.ghidra.service.listing.DataUnitResource;
import app.byteland.ghidra.service.listing.ListingService;
import app.byteland.ghidra.service.memory.MemoryService;
import app.byteland.ghidra.service.program.ProgramService;
import app.byteland.ghidra.service.reference.ReferenceService;
import app.byteland.ghidra.service.symbol.SymbolService;
import java.lang.reflect.Proxy;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class CodeUnitMethodsTest {

  @Test
  void wireNormalizationOfCodeUnitResourceIncludesValueAndRepresentationOnlyWhenNonNull() {
    CodeUnitResource withoutValues =
        new CodeUnitResource(
            "ram:00402004",
            CodeUnitResource.Kind.UNDEFINED,
            1,
            new ByteSequence(ByteSequence.Encoding.HEX, "00", 1),
            "?? 00h",
            null,
            null,
            DataTypeReference.named("/undefined"));

    Map<String, Object> normalizedUndefined = WireValues.resource(withoutValues);
    assertFalse(normalizedUndefined.containsKey("value"));
    assertFalse(normalizedUndefined.containsKey("representation"));

    CodeUnitResource definedData =
        new CodeUnitResource(
            "ram:00402000",
            CodeUnitResource.Kind.DATA,
            4,
            new ByteSequence(ByteSequence.Encoding.HEX, "2a000000", 4),
            "dd 2Ah",
            null,
            null,
            DataTypeReference.named("/dword"),
            "42",
            "2Ah");

    Map<String, Object> normalizedData = WireValues.resource(definedData);

    assertEquals("ram:00402000", normalizedData.get("address"));
    assertEquals("data", normalizedData.get("kind"));
    assertEquals(4, normalizedData.get("length"));
    assertEquals(
        Map.of("encoding", "hex", "data", "2a000000", "length", 4), normalizedData.get("bytes"));
    assertEquals("dd 2Ah", normalizedData.get("text"));
    assertEquals(Map.of("kind", "named", "name", "/dword"), normalizedData.get("data_type"));
    assertEquals("42", normalizedData.get("value"));
    assertEquals("2Ah", normalizedData.get("representation"));
  }

  @Test
  void codeUnitListEmitsValueAndRepresentationOnDataItemsAndSupportsProjection() throws Exception {
    CodeUnitResource instruction =
        new CodeUnitResource(
            "ram:00401000",
            CodeUnitResource.Kind.INSTRUCTION,
            1,
            new ByteSequence(ByteSequence.Encoding.HEX, "c3", 1),
            "RET",
            "RET",
            List.of(),
            null);
    CodeUnitResource data =
        new CodeUnitResource(
            "ram:00402000",
            CodeUnitResource.Kind.DATA,
            4,
            new ByteSequence(ByteSequence.Encoding.HEX, "2a000000", 4),
            "dd 2Ah",
            null,
            null,
            DataTypeReference.named("/dword"),
            "42",
            "2Ah");
    CodeUnitResource undefined =
        new CodeUnitResource(
            "ram:00402004",
            CodeUnitResource.Kind.UNDEFINED,
            1,
            new ByteSequence(ByteSequence.Encoding.HEX, "00", 1),
            "?? 00h",
            null,
            null,
            DataTypeReference.named("/undefined"));

    ApiRegistry registry =
        registryWithListing(
            (method, args) -> {
              assertEquals("listCodeUnits", method);
              return Page.of(List.of(instruction, data, undefined), (Integer) args[1], null);
            });

    @SuppressWarnings("unchecked")
    Map<String, Object> response =
        (Map<String, Object>) registry.dispatch("code_unit.list", Map.of());
    @SuppressWarnings("unchecked")
    List<Map<String, Object>> items = (List<Map<String, Object>>) response.get("items");

    assertEquals(3, items.size());
    assertEquals(
        Map.of(
            "address", "ram:00401000",
            "kind", "instruction",
            "length", 1,
            "bytes", Map.of("encoding", "hex", "data", "c3", "length", 1),
            "text", "RET",
            "mnemonic", "RET",
            "operands", List.of()),
        items.get(0));
    assertEquals(
        Map.of(
            "address", "ram:00402000",
            "kind", "data",
            "length", 4,
            "bytes", Map.of("encoding", "hex", "data", "2a000000", "length", 4),
            "text", "dd 2Ah",
            "data_type", Map.of("kind", "named", "name", "/dword"),
            "value", "42",
            "representation", "2Ah"),
        items.get(1));
    assertEquals(
        Map.of(
            "address", "ram:00402004",
            "kind", "undefined",
            "length", 1,
            "bytes", Map.of("encoding", "hex", "data", "00", "length", 1),
            "text", "?? 00h",
            "data_type", Map.of("kind", "named", "name", "/undefined")),
        items.get(2));

    @SuppressWarnings("unchecked")
    Map<String, Object> projected =
        (Map<String, Object>)
            registry.dispatch(
                "code_unit.list",
                Map.of(
                    "projection",
                    Map.of("fields", List.of("address", "kind", "value", "representation"))));
    @SuppressWarnings("unchecked")
    List<Map<String, Object>> projectedItems = (List<Map<String, Object>>) projected.get("items");
    assertEquals(Map.of("address", "ram:00401000", "kind", "instruction"), projectedItems.get(0));
    assertEquals(
        Map.of(
            "address", "ram:00402000",
            "kind", "data",
            "value", "42",
            "representation", "2Ah"),
        projectedItems.get(1));
    assertEquals(Map.of("address", "ram:00402004", "kind", "undefined"), projectedItems.get(2));

    ApiException error =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "code_unit.list",
                    Map.of("projection", Map.of("fields", List.of("unknown_field")))));
    assertEquals(400, error.status());
    assertEquals("invalid_enum", error.error().code());
  }

  @Test
  void dataUnitListStillExposesValueAndRepresentation() throws Exception {
    DataUnitResource dataUnit =
        new DataUnitResource(
            "ram:00402000",
            4,
            DataTypeReference.named("/dword"),
            "42",
            "2Ah",
            new ByteSequence(ByteSequence.Encoding.HEX, "2a000000", 4));

    ApiRegistry registry =
        registryWithListing(
            (method, args) -> {
              assertEquals("listDataUnits", method);
              return Page.of(List.of(dataUnit), (Integer) args[1], null);
            });

    @SuppressWarnings("unchecked")
    Map<String, Object> response =
        (Map<String, Object>) registry.dispatch("data_unit.list", Map.of());
    @SuppressWarnings("unchecked")
    List<Map<String, Object>> items = (List<Map<String, Object>>) response.get("items");

    assertEquals(
        List.of(
            Map.of(
                "address", "ram:00402000",
                "length", 4,
                "data_type", Map.of("kind", "named", "name", "/dword"),
                "value", "42",
                "representation", "2Ah",
                "bytes", Map.of("encoding", "hex", "data", "2a000000", "length", 4))),
        items);
  }

  private static ApiRegistry registryWithListing(Handler listingHandler) {
    ListingService listing = proxy(ListingService.class, listingHandler);
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
            unused(ReferenceService.class),
            unused(MemoryService.class),
            listing,
            unused(FunctionService.class),
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
