package app.byteland.ghidra.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.ByteSequence;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.ScanProgress;
import app.byteland.ghidra.service.TransactionRunner;
import app.byteland.ghidra.service.address.AddressResource;
import app.byteland.ghidra.service.address.AddressService;
import app.byteland.ghidra.service.analysis.AnalysisResource;
import app.byteland.ghidra.service.analysis.AnalysisService;
import app.byteland.ghidra.service.comment.CommentResource;
import app.byteland.ghidra.service.comment.CommentService;
import app.byteland.ghidra.service.datatype.DataTypePatch;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.datatype.DataTypeResource;
import app.byteland.ghidra.service.datatype.DataTypeService;
import app.byteland.ghidra.service.decompilation.DecompilationService;
import app.byteland.ghidra.service.function.FunctionService;
import app.byteland.ghidra.service.globalvariable.GlobalVariableResource;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService.Mutation;
import app.byteland.ghidra.service.globalvariable.GlobalVariableService.WriteMode;
import app.byteland.ghidra.service.listing.ListingService;
import app.byteland.ghidra.service.memory.MemoryBlockResource;
import app.byteland.ghidra.service.memory.MemoryResource;
import app.byteland.ghidra.service.memory.MemoryService;
import app.byteland.ghidra.service.program.ProgramService;
import app.byteland.ghidra.service.reference.ReferenceService;
import app.byteland.ghidra.service.symbol.SymbolService;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

class ApiMethodBuildersTest {
  @Test
  void pagedSchemaBuildersPreserveKeyOrderAndRequiredFields() {
    Map<String, Object> filter =
        WireSchema.object(
            ApiSchemaCatalog.props(
                "start", WireSchema.string(),
                "end", WireSchema.string(),
                "name", WireSchema.string()));

    Map<String, Object> listInput = ApiSchemaCatalog.listInput(filter);
    assertEquals(
        List.of("filter", "limit", "cursor", "fields"), propertyKeys(listInput));
    assertFalse(listInput.containsKey("required"));
    Map<String, Object> canonicalListInput = StrictObjectCodec.canonicalSchema(listInput);
    assertEquals(List.of("filter", "page", "projection"), propertyKeys(canonicalListInput));
    assertEquals(List.of("start", "end", "name"), nestedPropertyKeys(canonicalListInput, "filter"));
    assertEquals(List.of("limit", "cursor"), nestedPropertyKeys(canonicalListInput, "page"));
    assertEquals(List.of("fields"), nestedPropertyKeys(canonicalListInput, "projection"));

    Map<String, Object> scanListInput = ApiSchemaCatalog.scanListInput(filter);
    assertEquals(
        List.of("filter", "range", "timeout_ms", "limit", "cursor", "fields"),
        propertyKeys(scanListInput));
    assertFalse(scanListInput.containsKey("required"));
    Map<String, Object> canonicalScanInput = StrictObjectCodec.canonicalSchema(scanListInput);
    assertEquals(List.of("filter", "page", "scan", "projection"), propertyKeys(canonicalScanInput));
    assertEquals(List.of("start", "end", "name"), nestedPropertyKeys(canonicalScanInput, "filter"));
    assertEquals(List.of("range", "timeout_ms"), nestedPropertyKeys(canonicalScanInput, "scan"));

    Map<String, Object> requiredListInput = ApiSchemaCatalog.requiredListInput(filter);
    assertEquals(
        List.of("filter", "limit", "cursor", "fields"), propertyKeys(requiredListInput));
    assertEquals(List.of("filter"), requiredListInput.get("required"));
    assertEquals(
        List.of("filter"), StrictObjectCodec.canonicalSchema(requiredListInput).get("required"));

    Map<String, Object> requiredScanListInput = ApiSchemaCatalog.requiredScanListInput(filter);
    assertEquals(
        List.of("filter", "timeout_ms", "limit", "cursor", "fields"),
        propertyKeys(requiredScanListInput));
    assertEquals(List.of("filter"), requiredScanListInput.get("required"));
    Map<String, Object> canonicalRequiredScan =
        StrictObjectCodec.canonicalSchema(requiredScanListInput);
    assertEquals(
        List.of("filter", "page", "scan", "projection"), propertyKeys(canonicalRequiredScan));
    assertEquals(List.of("timeout_ms"), nestedPropertyKeys(canonicalRequiredScan, "scan"));
    assertEquals(
        List.of("start", "end", "name"), nestedPropertyKeys(canonicalRequiredScan, "filter"));
    assertEquals(List.of("filter"), canonicalRequiredScan.get("required"));

    Set<String> fields = Set.of("address", "name");
    List<String> identity = List.of("address");
    Map<String, Object> itemsSchema = ApiSchemaCatalog.itemsSchema(fields, identity);
    assertEquals(List.of("items"), propertyKeys(itemsSchema));
    assertEquals(List.of("items"), itemsSchema.get("required"));

    Map<String, Object> listSchema = ApiSchemaCatalog.listSchema(fields, identity);
    assertEquals(List.of("items", "next_cursor"), propertyKeys(listSchema));
    assertEquals(List.of("items"), listSchema.get("required"));

    Map<String, Object> scanListSchema = ApiSchemaCatalog.scanListSchema(fields, identity);
    assertEquals(List.of("items", "next_cursor", "scan"), propertyKeys(scanListSchema));
    assertEquals(List.of("items"), scanListSchema.get("required"));
  }

  @Test
  void pagedAndReadBuildersDispatchWithoutTransactionsAndPreserveCursors() throws Exception {
    AtomicInteger transactions = new AtomicInteger();
    AtomicReference<String> receivedBlockCursor = new AtomicReference<>();
    AtomicReference<String> receivedCommentCursor = new AtomicReference<>();

    MemoryService memory =
        proxy(
            MemoryService.class,
            (method, args) -> {
              if ("getMemoryBlockByName".equals(method)) {
                return new MemoryBlockResource(
                    ".text",
                    "0x1000",
                    "0x1fff",
                    4096,
                    true,
                    false,
                    true,
                    true,
                    false,
                    false,
                    MemoryBlockResource.Kind.DEFAULT,
                    null);
              }
              assertEquals("listMemoryBlocks", method);
              MemoryService.MemoryBlockQuery query = (MemoryService.MemoryBlockQuery) args[0];
              receivedBlockCursor.set(query.cursor());
              if (query.cursor() == null) {
                return Page.of(
                    List.of(
                        new MemoryBlockResource(
                            ".rodata",
                            "0x2000",
                            "0x20ff",
                            256,
                            true,
                            false,
                            false,
                            true,
                            false,
                            false,
                            MemoryBlockResource.Kind.DEFAULT,
                            null),
                        new MemoryBlockResource(
                            ".bss",
                            "0x3000",
                            "0x30ff",
                            256,
                            true,
                            true,
                            false,
                            false,
                            false,
                            false,
                            MemoryBlockResource.Kind.DEFAULT,
                            null)),
                    query.limit(),
                    ".rodata");
              }
              return Page.of(List.of(), query.limit(), null);
            });

    CommentService comments =
        proxy(
            CommentService.class,
            (method, args) -> {
              assertEquals("listComments", method);
              CommentService.CommentQuery query = (CommentService.CommentQuery) args[0];
              receivedCommentCursor.set(query.cursor());
              ScanProgress progress =
                  new ScanProgress(
                      ScanProgress.Kind.ADDRESS,
                      "0x1000",
                      "0x2000",
                      "0x1000",
                      "0x1010",
                      false,
                      ScanProgress.StopReason.LIMIT,
                      5L);
              return Page.scanned(
                  List.of(
                      new CommentResource("0x1010", CommentResource.Type.EOL, "second"),
                      new CommentResource("0x1000", CommentResource.Type.PRE, "first")),
                  query.limit(),
                  "0x1010:eol",
                  progress);
            });

    ApiRegistry registry = registryWith(
        transactions, memory, unused(AddressService.class), comments,
        unused(GlobalVariableService.class), unused(DataTypeService.class));

    Map<?, ?> singleBlock =
        (Map<?, ?>)
            registry.dispatch(
                "memory_block.get",
                Map.of(
                    "selector", Map.of("name", ".text"),
                    "projection", Map.of("fields", List.of("start"))));
    assertEquals(Map.of("name", ".text", "start", "0x1000"), singleBlock);

    Map<?, ?> firstPage =
        (Map<?, ?>)
            registry.dispatch(
                "memory_block.list",
                Map.of(
                    "page", Map.of("limit", 2),
                    "projection", Map.of("fields", List.of("start"))));
    List<?> blocks = (List<?>) firstPage.get("items");
    assertEquals(".rodata", ((Map<?, ?>) blocks.get(0)).get("name"));
    assertEquals(".bss", ((Map<?, ?>) blocks.get(1)).get("name"));
    String blockNextCursor = (String) firstPage.get("next_cursor");
    assertTrue(blockNextCursor != null && !blockNextCursor.isBlank());
    assertFalse(firstPage.containsKey("scan"));

    Map<?, ?> secondPage =
        (Map<?, ?>)
            registry.dispatch(
                "memory_block.list",
                Map.of(
                    "page", Map.of("limit", 2, "cursor", blockNextCursor),
                    "projection", Map.of("fields", List.of("start"))));
    assertEquals(".rodata", receivedBlockCursor.get());
    assertEquals(List.of(), secondPage.get("items"));
    assertFalse(secondPage.containsKey("next_cursor"));

    Map<?, ?> scannedPage =
        (Map<?, ?>)
            registry.dispatch(
                "comment.list",
                Map.of("scan", Map.of("range", Map.of("start", "0x1000", "end", "0x2000"))));
    List<?> commentsOut = (List<?>) scannedPage.get("items");
    assertEquals("0x1010", ((Map<?, ?>) commentsOut.get(0)).get("address"));
    assertEquals("0x1000", ((Map<?, ?>) commentsOut.get(1)).get("address"));
    Map<?, ?> scanOut = (Map<?, ?>) scannedPage.get("scan");
    assertEquals("limit", scanOut.get("stop_reason"));
    String commentNextCursor = (String) scannedPage.get("next_cursor");

    registry.dispatch(
        "comment.list",
        Map.of(
            "scan", Map.of("range", Map.of("start", "0x1000", "end", "0x2000")),
            "page", Map.of("cursor", commentNextCursor)));
    assertEquals("0x1010:eol", receivedCommentCursor.get());
    assertEquals(0, transactions.get());
  }

  @Test
  void memorySchemasAndDispatchShareFieldSetAndByteSequenceSchema() throws Exception {
    AtomicInteger transactions = new AtomicInteger();
    AtomicReference<ByteSequence> patchedBytes = new AtomicReference<>();

    MemoryService memory =
        proxy(
            MemoryService.class,
            (method, args) -> {
              if ("readMemoryRange".equals(method)) {
                return new MemoryResource(
                    "0x1000", new ByteSequence(ByteSequence.Encoding.HEX, "9090", 2));
              }
              assertEquals("patchMemory", method);
              patchedBytes.set((ByteSequence) args[1]);
              return null;
            });
    AddressService addresses =
        raw -> new AddressResource("ram:00001000", true, true, null, null, null, null);

    ApiRegistry registry =
        registryWith(
            transactions,
            memory,
            addresses,
            unused(CommentService.class),
            unused(GlobalVariableService.class),
            unused(DataTypeService.class));

    ApiMethod<Map<String, Object>, Object> readMethod = registry.method("memory.read");
    assertEquals(
        Set.of("address", "bytes", "bytes.encoding", "bytes.data", "bytes.length"),
        readMethod.fields());
    assertEquals(
        ApiSchemaCatalog.resourceSchema(readMethod.fields(), readMethod.identityFields()),
        readMethod.responseCodec().schema());

    @SuppressWarnings("unchecked")
    Map<String, Object> writeProperties =
        (Map<String, Object>) registry.method("memory.write").requestCodec().schema().get("properties");
    @SuppressWarnings("unchecked")
    Map<String, Object> patchSchema = (Map<String, Object>) writeProperties.get("patch");
    @SuppressWarnings("unchecked")
    Map<String, Object> patchProperties = (Map<String, Object>) patchSchema.get("properties");
    assertEquals(ApiSchemaCatalog.byteSequenceSchema(), patchProperties.get("bytes"));

    Map<?, ?> readResult =
        (Map<?, ?>)
            registry.dispatch(
                "memory.read",
                Map.of(
                    "selector", Map.of("address", "0x1000"),
                    "projection", Map.of("fields", List.of("bytes.data"))));
    assertEquals(Map.of("address", "0x1000", "bytes", Map.of("data", "9090")), readResult);
    assertEquals(0, transactions.get());

    Map<?, ?> writeResult =
        (Map<?, ?>)
            registry.dispatch(
                "memory.write",
                Map.of(
                    "selector", Map.of("address", "0x1000"),
                    "patch",
                        Map.of(
                            "bytes",
                            Map.of("encoding", "hex", "data", "cc90", "length", 2))));
    assertEquals(Map.of("start", "ram:00001000", "length", 2), writeResult);
    assertEquals(new ByteSequence(ByteSequence.Encoding.HEX, "cc90", 2), patchedBytes.get());
    assertEquals(1, transactions.get());
  }

  @Test
  void globalVariableAndCommentWriteBuildersPreserveOrderSchemasAndEffects() throws Exception {
    AtomicInteger transactions = new AtomicInteger();
    List<WriteMode> globalModes = new ArrayList<>();
    AtomicReference<Mutation> lastMutation = new AtomicReference<>();
    AtomicReference<CommentResource> storedComment = new AtomicReference<>();

    GlobalVariableService globals =
        proxy(
            GlobalVariableService.class,
            (method, args) -> {
              if ("writeGlobalVariable".equals(method)) {
                lastMutation.set((Mutation) args[0]);
                globalModes.add((WriteMode) args[1]);
                return null;
              }
              assertEquals("getGlobalVariable", method);
              return new GlobalVariableResource(
                  (String) args[0],
                  "g_counter",
                  "Global",
                  DataTypeReference.named("int"),
                  4,
                  "0",
                  "0h",
                  "user_defined");
            });

    CommentService comments =
        proxy(
            CommentService.class,
            (method, args) -> {
              if ("listComments".equals(method)) {
                CommentResource current = storedComment.get();
                return Page.of(current == null ? List.of() : List.of(current), 2, null);
              }
              assertEquals("setComment", method);
              storedComment.set(
                  new CommentResource(
                      (String) args[0], (CommentResource.Type) args[1], (String) args[2]));
              return null;
            });

    ApiRegistry registry =
        registryWith(
            transactions,
            unused(MemoryService.class),
            unused(AddressService.class),
            comments,
            globals,
            unused(DataTypeService.class));

    List<String> names =
        registry.methodCatalog().methods().stream()
            .map(ApiCatalog.MethodDescriptor::name)
            .toList();
    int gvCreateIndex = names.indexOf("global_variable.create");
    int gvPatchIndex = names.indexOf("global_variable.patch");
    int gvUpsertIndex = names.indexOf("global_variable.upsert");
    assertTrue(gvCreateIndex < gvPatchIndex && gvPatchIndex < gvUpsertIndex);

    int commentCreateIndex = names.indexOf("comment.create");
    int commentPatchIndex = names.indexOf("comment.patch");
    int commentUpsertIndex = names.indexOf("comment.upsert");
    assertTrue(commentCreateIndex < commentPatchIndex && commentPatchIndex < commentUpsertIndex);

    assertEquals(
        registry.method("global_variable.create").requestCodec().schema(),
        registry.method("global_variable.upsert").requestCodec().schema());
    assertFalse(registry.method("global_variable.create").effects().destructive());
    assertFalse(registry.method("global_variable.create").effects().idempotent());
    assertTrue(registry.method("global_variable.upsert").effects().destructive());
    assertTrue(registry.method("global_variable.upsert").effects().idempotent());

    Map<String, Object> gvParams =
        Map.of(
            "resource",
            Map.of(
                "address", "0x4000",
                "name", "g_counter",
                "data_type", Map.of("kind", "named", "name", "int")));
    Map<?, ?> createdGv = (Map<?, ?>) registry.dispatch("global_variable.create", gvParams);
    Map<?, ?> upsertedGv = (Map<?, ?>) registry.dispatch("global_variable.upsert", gvParams);
    assertEquals(List.of(WriteMode.CREATE, WriteMode.UPSERT), globalModes);
    assertEquals("g_counter", lastMutation.get().name());
    assertEquals(createdGv, upsertedGv);

    assertEquals(
        registry.method("comment.create").requestCodec().schema(),
        registry.method("comment.upsert").requestCodec().schema());
    assertFalse(registry.method("comment.create").effects().destructive());
    assertFalse(registry.method("comment.create").effects().idempotent());
    assertTrue(registry.method("comment.upsert").effects().destructive());
    assertTrue(registry.method("comment.upsert").effects().idempotent());

    Map<String, Object> commentParams =
        Map.of("resource", Map.of("address", "0x1000", "type", "eol", "text", "initial"));
    Map<?, ?> createdComment = (Map<?, ?>) registry.dispatch("comment.create", commentParams);
    assertEquals(Map.of("address", "0x1000", "type", "eol", "text", "initial"), createdComment);

    ApiException duplicate =
        assertThrows(ApiException.class, () -> registry.dispatch("comment.create", commentParams));
    assertEquals(409, duplicate.status());
    assertEquals("comment_exists", duplicate.error().code());

    Map<?, ?> upsertedComment =
        (Map<?, ?>)
            registry.dispatch(
                "comment.upsert",
                Map.of("resource", Map.of("address", "0x1000", "type", "eol", "text", "updated")));
    assertEquals(Map.of("address", "0x1000", "type", "eol", "text", "updated"), upsertedComment);
    assertEquals(5, transactions.get());
  }

  @Test
  void compositeDataTypePatchesShareFieldConversionAndPointerOrder() throws Exception {
    AtomicInteger transactions = new AtomicInteger();
    List<DataTypePatch> receivedPatches = new ArrayList<>();

    DataTypeService dataTypes =
        proxy(
            DataTypeService.class,
            (method, args) -> {
              if ("patchDataType".equals(method)) {
                receivedPatches.add((DataTypePatch) args[1]);
                return null;
              }
              assertEquals("getDataType", method);
              String path = (String) args[0];
              DataTypeResource.Kind kind =
                  path.endsWith("Union") ? DataTypeResource.Kind.UNION : DataTypeResource.Kind.STRUCT;
              return new DataTypeResource(
                  path, path.substring(1), "/", kind, 4, null, 4, List.of(), null, null, null);
            });

    ApiRegistry registry =
        registryWith(
            transactions,
            unused(MemoryService.class),
            unused(AddressService.class),
            unused(CommentService.class),
            unused(GlobalVariableService.class),
            dataTypes);

    Map<String, Object> addField =
        Map.of("name", "a", "data_type", Map.of("kind", "named", "name", "int"));
    Map<String, Object> renameField = Map.of("name", "a", "new_name", "b");
    Map<String, Object> updateField = Map.of("name", "b", "length", 4);
    Map<String, Object> removeField = Map.of("name", "old");

    registry.dispatch(
        "data_type.patch",
        Map.of(
            "selector", Map.of("path", "/DemoStruct"),
            "patch",
                Map.of(
                    "kind", "struct",
                    "add_fields", List.of(addField),
                    "rename_fields", List.of(renameField),
                    "update_fields", List.of(updateField),
                    "remove_fields", List.of(removeField))));
    registry.dispatch(
        "data_type.patch",
        Map.of(
            "selector", Map.of("path", "/DemoUnion"),
            "patch",
                Map.of(
                    "kind", "union",
                    "add_fields", List.of(addField),
                    "rename_fields", List.of(renameField),
                    "update_fields", List.of(updateField),
                    "remove_fields", List.of(removeField))));

    DataTypePatch.Struct structPatch =
        assertInstanceOf(DataTypePatch.Struct.class, receivedPatches.get(0));
    DataTypePatch.Union unionPatch =
        assertInstanceOf(DataTypePatch.Union.class, receivedPatches.get(1));
    assertEquals(structPatch.addFields(), unionPatch.addFields());
    assertEquals(structPatch.renameFields(), unionPatch.renameFields());
    assertEquals(structPatch.updateFields(), unionPatch.updateFields());
    assertEquals(structPatch.removeFields(), unionPatch.removeFields());
    assertFalse(registry.method("data_type.patch").effects().idempotent());
    assertEquals(2, transactions.get());

    ApiMethod<Map<String, Object>, Object> patchMethod = registry.method("data_type.patch");
    for (String kind : List.of("struct", "union")) {
      Map<String, Object> invalidField =
          Map.of("name", "bad", "data_type", Map.of("kind", "unsupported"));
      Map<String, Object> patchAllInvalid = new LinkedHashMap<>();
      patchAllInvalid.put("kind", kind);
      patchAllInvalid.put("remove_fields", List.of(invalidField));
      patchAllInvalid.put("update_fields", List.of(invalidField));
      patchAllInvalid.put("rename_fields", List.of(invalidField));
      patchAllInvalid.put("add_fields", List.of(invalidField));
      ApiException firstFailure =
          assertThrows(
              ApiException.class,
              () ->
                  patchMethod.invokeDecoded(
                      Map.of("selector", Map.of("path", "/Demo"), "patch", patchAllInvalid)));
      assertEquals("/patch/add_fields/0/data_type/kind", firstFailure.error().target());

      patchAllInvalid.remove("add_fields");
      ApiException secondFailure =
          assertThrows(
              ApiException.class,
              () ->
                  patchMethod.invokeDecoded(
                      Map.of("selector", Map.of("path", "/Demo"), "patch", patchAllInvalid)));
      assertEquals("/patch/rename_fields/0/data_type/kind", secondFailure.error().target());

      patchAllInvalid.remove("rename_fields");
      ApiException thirdFailure =
          assertThrows(
              ApiException.class,
              () ->
                  patchMethod.invokeDecoded(
                      Map.of("selector", Map.of("path", "/Demo"), "patch", patchAllInvalid)));
      assertEquals("/patch/update_fields/0/data_type/kind", thirdFailure.error().target());

      patchAllInvalid.remove("update_fields");
      ApiException fourthFailure =
          assertThrows(
              ApiException.class,
              () ->
                  patchMethod.invokeDecoded(
                      Map.of("selector", Map.of("path", "/Demo"), "patch", patchAllInvalid)));
      assertEquals("/patch/remove_fields/0/data_type/kind", fourthFailure.error().target());
    }
  }

  @SuppressWarnings("unchecked")
  private static List<String> propertyKeys(Map<String, Object> schema) {
    Map<String, Object> properties = (Map<String, Object>) schema.get("properties");
    return List.copyOf(properties.keySet());
  }

  @SuppressWarnings("unchecked")
  private static List<String> nestedPropertyKeys(Map<String, Object> schema, String key) {
    Map<String, Object> properties = (Map<String, Object>) schema.get("properties");
    return propertyKeys((Map<String, Object>) properties.get(key));
  }

  private static ApiRegistry registryWith(
      AtomicInteger transactions,
      MemoryService memory,
      AddressService addresses,
      CommentService comments,
      GlobalVariableService globals,
      DataTypeService dataTypes) {
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
            transactions.incrementAndGet();
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
            addresses,
            comments,
            unused(ReferenceService.class),
            memory,
            unused(ListingService.class),
            unused(FunctionService.class),
            globals,
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
