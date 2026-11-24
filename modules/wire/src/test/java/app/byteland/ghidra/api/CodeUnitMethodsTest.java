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
  void wireNormalizationOfCodeUnitResourceOmitsValueAndRepresentation() {
    CodeUnitResource item =
        new CodeUnitResource(
            "ram:00402000",
            CodeUnitResource.Kind.DATA,
            4,
            new ByteSequence(ByteSequence.Encoding.HEX, "2a000000", 4),
            "dd 2Ah",
            null,
            null,
            DataTypeReference.named("/dword"));

    Map<String, Object> normalized = WireValues.resource(item);

    assertEquals("ram:00402000", normalized.get("address"));
    assertEquals("data", normalized.get("kind"));
    assertEquals(4, normalized.get("length"));
    assertEquals(
        Map.of("encoding", "hex", "data", "2a000000", "length", 4), normalized.get("bytes"));
    assertEquals("dd 2Ah", normalized.get("text"));
    assertEquals(Map.of("kind", "named", "name", "/dword"), normalized.get("data_type"));
    assertFalse(normalized.containsKey("value"));
    assertFalse(normalized.containsKey("representation"));
  }

  @Test
  void codeUnitListReturnsEightFieldSchemaAndRejectsValueOrRepresentationProjections()
      throws Exception {
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
            DataTypeReference.named("/dword"));
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
        registryWithListing((method, args) -> {
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
            "address",
            "ram:00402000",
            "kind",
            "data",
            "length",
            4,
            "bytes",
            Map.of("encoding", "hex", "data", "2a000000", "length", 4),
            "text",
            "dd 2Ah",
            "data_type",
            Map.of("kind", "named", "name", "/dword")),
        items.get(1));
    assertEquals(
        Map.of(
            "address",
            "ram:00402004",
            "kind",
            "undefined",
            "length",
            1,
            "bytes",
            Map.of("encoding", "hex", "data", "00", "length", 1),
            "text",
            "?? 00h",
            "data_type",
            Map.of("kind", "named", "name", "/undefined")),
        items.get(2));

    for (String disallowedField : List.of("value", "representation")) {
      ApiException error =
          assertThrows(
              ApiException.class,
              () ->
                  registry.dispatch(
                      "code_unit.list",
                      Map.of("projection", Map.of("fields", List.of(disallowedField)))));
      assertEquals(400, error.status());
      assertEquals("invalid_enum", error.error().code());
    }
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
        registryWithListing((method, args) -> {
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
                "address",
                "ram:00402000",
                "length",
                4,
                "data_type",
                Map.of("kind", "named", "name", "/dword"),
                "value",
                "42",
                "representation",
                "2Ah",
                "bytes",
                Map.of("encoding", "hex", "data", "2a000000", "length", 4))),
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
