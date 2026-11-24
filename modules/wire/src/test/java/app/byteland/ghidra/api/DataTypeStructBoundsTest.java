package app.byteland.ghidra.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.JsonUtil;
import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.TransactionRunner;
import app.byteland.ghidra.service.address.AddressService;
import app.byteland.ghidra.service.analysis.AnalysisResource;
import app.byteland.ghidra.service.analysis.AnalysisService;
import app.byteland.ghidra.service.comment.CommentService;
import app.byteland.ghidra.service.datatype.DataTypePatch;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.datatype.DataTypeResource;
import app.byteland.ghidra.service.datatype.DataTypeService;
import app.byteland.ghidra.service.decompilation.DecompilationService;
import app.byteland.ghidra.service.function.FunctionService;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService;
import app.byteland.ghidra.service.listing.ListingService;
import app.byteland.ghidra.service.memory.MemoryService;
import app.byteland.ghidra.service.program.ProgramService;
import app.byteland.ghidra.service.reference.ReferenceService;
import app.byteland.ghidra.service.symbol.SymbolService;
import java.lang.reflect.Proxy;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import org.junit.jupiter.api.Test;

class DataTypeStructBoundsTest {
  @Test
  void rejectsOversizedStructSizeOffsetAndLengthAtSchemaBoundary() {
    ApiRegistry registry = registryWithDataTypes(unused(DataTypeService.class));

    ApiException oversizedCreate =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "data_type.create",
                    Map.of(
                        "resource",
                        Map.of(
                            "kind",
                            "struct",
                            "name",
                            "oversized",
                            "size",
                            ApiSchemaCatalog.MAX_STRUCT_SIZE + 1))));
    assertEquals(400, oversizedCreate.status());
    assertEquals("/resource/size", oversizedCreate.error().target());

    ApiException maxIntCreate =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "data_type.create",
                    Map.of(
                        "resource",
                        Map.of(
                            "kind",
                            "struct",
                            "name",
                            "max_int",
                            "size",
                            Integer.MAX_VALUE))));
    assertEquals(400, maxIntCreate.status());
    assertEquals("/resource/size", maxIntCreate.error().target());

    ApiException oversizedOffset =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "data_type.patch",
                    Map.of(
                        "selector",
                        Map.of("path", "/marker_patch"),
                        "patch",
                        Map.of(
                            "kind",
                            "struct",
                            "add_fields",
                            List.of(
                                Map.of(
                                    "name",
                                    "tail_byte",
                                    "offset",
                                    ApiSchemaCatalog.MAX_STRUCT_SIZE + 1,
                                    "data_type",
                                    Map.of("kind", "named", "name", "byte")))))));
    assertEquals(400, oversizedOffset.status());
    assertEquals("/patch/add_fields/0/offset", oversizedOffset.error().target());

    ApiException oversizedLength =
        assertThrows(
            ApiException.class,
            () ->
                registry.dispatch(
                    "data_type.patch",
                    Map.of(
                        "selector",
                        Map.of("path", "/marker_patch"),
                        "patch",
                        Map.of(
                            "kind",
                            "struct",
                            "add_fields",
                            List.of(
                                Map.of(
                                    "name",
                                    "tail_slice",
                                    "offset",
                                    0,
                                    "length",
                                    ApiSchemaCatalog.MAX_STRUCT_SIZE + 1,
                                    "data_type",
                                    Map.of("kind", "named", "name", "byte")))))));
    assertEquals(400, oversizedLength.status());
    assertEquals("/patch/add_fields/0/length", oversizedLength.error().target());
  }

  @Test
  @SuppressWarnings("unchecked")
  void dispatchesSparseStructOperationsWithinMaxStructSize() throws Exception {
    Map<String, DataTypeResource> store = new LinkedHashMap<>();
    store.put(
        "/marker_patch",
        new DataTypeResource(
            "/marker_patch",
            "marker_patch",
            "/",
            DataTypeResource.Kind.STRUCT,
            0,
            "",
            0,
            List.of(),
            null,
            null,
            null));

    DataTypeService dataTypes =
        proxy(
            DataTypeService.class,
            (method, args) ->
                switch (method) {
                  case "getDataType" -> {
                    DataTypeResource found = store.get((String) args[0]);
                    if (found == null) throw new NoSuchElementException((String) args[0]);
                    yield found;
                  }
                  case "createDataType" -> {
                    String name = (String) args[2];
                    int size = (Integer) args[4];
                    store.put(
                        "/" + name,
                        new DataTypeResource(
                            "/" + name,
                            name,
                            "/",
                            DataTypeResource.Kind.STRUCT,
                            size,
                            "",
                            size,
                            List.of(),
                            null,
                            null,
                            null));
                    yield null;
                  }
                  case "patchDataType" -> {
                    String path = (String) args[0];
                    DataTypePatch.Struct patch = (DataTypePatch.Struct) args[1];
                    if (patch.addFields() != null && !patch.addFields().isEmpty()) {
                      DataTypePatch.CompositeField added = patch.addFields().getFirst();
                      int offset = added.offset() == null ? 0 : added.offset();
                      store.put(
                          path,
                          new DataTypeResource(
                              path,
                              "marker_patch",
                              "/",
                              DataTypeResource.Kind.STRUCT,
                              offset + 1,
                              "",
                              offset + 1,
                              List.of(
                                  new DataTypeResource.Field(
                                      offset,
                                      added.name(),
                                      offset,
                                      offset,
                                      DataTypeResource.Kind.BUILTIN,
                                      1,
                                      null,
                                      false,
                                      DataTypeReference.named("byte"))),
                              null,
                              null,
                              null));
                    }
                    yield null;
                  }
                  default -> throw new AssertionError(method);
                });

    ApiRegistry registry = registryWithDataTypes(dataTypes);

    Map<String, Object> createCall =
        JsonUtil.parseObject(
            "{\"operation\":\"create\",\"params\":{\"resource\":"
                + "{\"kind\":\"struct\",\"name\":\"marker_create\",\"size\":25000}}}");
    Map<String, Object> created =
        (Map<String, Object>)
            registry.dispatch("data_type.create", (Map<String, Object>) createCall.get("params"));
    assertEquals("/marker_create", created.get("path"));
    assertEquals(25000, ((Number) created.get("size")).intValue());
    assertEquals(List.of(), created.get("fields"));

    Map<String, Object> patchAddCall =
        JsonUtil.parseObject(
            "{\"operation\":\"patch\",\"params\":{\"selector\":{\"path\":\"/marker_patch\"},"
                + "\"patch\":{\"kind\":\"struct\",\"add_fields\":[{\"name\":\"tail_byte\","
                + "\"offset\":25000,\"data_type\":{\"kind\":\"named\",\"name\":\"byte\"}}]}}}");
    Map<String, Object> patched =
        (Map<String, Object>)
            registry.dispatch("data_type.patch", (Map<String, Object>) patchAddCall.get("params"));
    List<Map<String, Object>> fields = (List<Map<String, Object>>) patched.get("fields");
    assertEquals(1, fields.size());
    assertEquals("tail_byte", fields.getFirst().get("name"));
    assertEquals(25000, ((Number) fields.getFirst().get("offset")).intValue());

    Map<String, Object> patchRemoveCall =
        JsonUtil.parseObject(
            "{\"operation\":\"patch\",\"params\":{\"selector\":{\"path\":\"/marker_patch\"},"
                + "\"patch\":{\"kind\":\"struct\",\"remove_fields\":"
                + "[{\"name\":\"missing_field_0\"}]}}}");
    Map<String, Object> afterRemove =
        (Map<String, Object>)
            registry.dispatch(
                "data_type.patch", (Map<String, Object>) patchRemoveCall.get("params"));
    assertTrue(((List<?>) afterRemove.get("fields")).size() == 1);

    Map<String, Object> maxBoundCreated =
        (Map<String, Object>)
            registry.dispatch(
                "data_type.create",
                Map.of(
                    "resource",
                    Map.of(
                        "kind",
                        "struct",
                        "name",
                        "max_bound_struct",
                        "size",
                        ApiSchemaCatalog.MAX_STRUCT_SIZE)));
    assertEquals(ApiSchemaCatalog.MAX_STRUCT_SIZE, ((Number) maxBoundCreated.get("size")).intValue());
  }

  private static ApiRegistry registryWithDataTypes(DataTypeService dataTypes) {
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
            } catch (RuntimeException ex) {
              throw ex;
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
            unused(ListingService.class),
            unused(FunctionService.class),
            unused(GlobalVariableService.class),
            analysis,
            unused(DecompilationService.class),
            unused(SymbolService.class),
            dataTypes,
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
