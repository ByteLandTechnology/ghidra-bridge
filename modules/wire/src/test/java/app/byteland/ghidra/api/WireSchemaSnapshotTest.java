package app.byteland.ghidra.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.JsonUtil;
import app.byteland.ghidra.api.ApiMethod.McpAnnotations;
import app.byteland.ghidra.api.ApiMethod.MethodEffects;
import app.byteland.ghidra.service.TransactionRunner;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.DoubleAdder;
import org.junit.jupiter.api.Test;

class WireSchemaSnapshotTest {
  @Test
  void snapshotPreservesEightImmutableNumbersNullsAndKeyOrder() {
    Map<String, Object> numbers = new LinkedHashMap<>();
    numbers.put("byte", (byte) 1);
    numbers.put("short", (short) 2);
    numbers.put("int", 3);
    numbers.put("long", 4L);
    numbers.put("float", 5.5f);
    numbers.put("double", 6.25d);
    numbers.put("big_int", BigInteger.valueOf(7));
    numbers.put("big_decimal", new BigDecimal("8.125"));

    List<Object> listWithNull = new ArrayList<>(Arrays.asList("alpha", null, 42, false));
    Map<String, Object> source = new LinkedHashMap<>();
    source.put("z_text", "hello");
    source.put("a_flag", true);
    source.put("m_null", null);
    source.put("numbers", numbers);
    source.put("items", listWithNull);

    Map<String, Object> frozen = WireSchema.snapshot(source);

    assertEquals(List.of("z_text", "a_flag", "m_null", "numbers", "items"),
        List.copyOf(frozen.keySet()));
    assertEquals("hello", frozen.get("z_text"));
    assertEquals(true, frozen.get("a_flag"));
    assertTrue(frozen.containsKey("m_null"));
    assertNull(frozen.get("m_null"));

    @SuppressWarnings("unchecked")
    Map<String, Object> frozenNumbers = (Map<String, Object>) frozen.get("numbers");
    assertEquals(
        List.of("byte", "short", "int", "long", "float", "double", "big_int", "big_decimal"),
        List.copyOf(frozenNumbers.keySet()));
    assertEquals((byte) 1, frozenNumbers.get("byte"));
    assertEquals((short) 2, frozenNumbers.get("short"));
    assertEquals(3, frozenNumbers.get("int"));
    assertEquals(4L, frozenNumbers.get("long"));
    assertEquals(5.5f, frozenNumbers.get("float"));
    assertEquals(6.25d, frozenNumbers.get("double"));
    assertEquals(BigInteger.valueOf(7), frozenNumbers.get("big_int"));
    assertEquals(new BigDecimal("8.125"), frozenNumbers.get("big_decimal"));

    @SuppressWarnings("unchecked")
    List<Object> frozenItems = (List<Object>) frozen.get("items");
    assertEquals(Arrays.asList("alpha", null, 42, false), frozenItems);

    // Mutating caller-owned containers does not affect the snapshot.
    source.put("extra", "mutated");
    numbers.put("byte", (byte) 99);
    listWithNull.set(0, "changed");
    assertFalse(frozen.containsKey("extra"));
    assertEquals((byte) 1, frozenNumbers.get("byte"));
    assertEquals("alpha", frozenItems.getFirst());

    // Returned Map and List views are deeply unmodifiable.
    assertThrows(UnsupportedOperationException.class, () -> frozen.put("x", 1));
    assertThrows(UnsupportedOperationException.class, () -> frozenNumbers.put("int", 0));
    assertThrows(UnsupportedOperationException.class, () -> frozenItems.add("new"));
  }

  @Test
  void snapshotRejectsInvalidKeysMutableNumbersAndNonListCollectionsWithNeutralErrors() {
    NullPointerException nullSchema =
        assertThrows(NullPointerException.class, () -> WireSchema.snapshot(null));
    assertEquals("schema", nullSchema.getMessage());

    Map<Object, Object> integerKey = new LinkedHashMap<>();
    integerKey.put(42, "string");
    IllegalArgumentException keyError =
        assertThrows(IllegalArgumentException.class, () -> WireSchema.snapshot(integerKey));
    assertEquals("schema object keys must be strings", keyError.getMessage());

    Map<Object, Object> nullKey = new HashMap<>();
    nullKey.put(null, "string");
    IllegalArgumentException nullKeyError =
        assertThrows(IllegalArgumentException.class, () -> WireSchema.snapshot(nullKey));
    assertEquals("schema object keys must be strings", nullKeyError.getMessage());

    List<Object> unsupportedValues = List.of(
        new AtomicInteger(1),
        new AtomicLong(2L),
        new DoubleAdder(),
        new LinkedHashSet<>(List.of("a")),
        new ArrayDeque<>(List.of("a")),
        new String[] {"a"});

    for (Object invalid : unsupportedValues) {
      Map<String, Object> inMap = Map.of("bad", invalid);
      IllegalArgumentException mapError =
          assertThrows(IllegalArgumentException.class, () -> WireSchema.snapshot(inMap));
      assertEquals(
          "unsupported schema value: " + invalid.getClass().getName(), mapError.getMessage());

      Map<String, Object> inList = Map.of("items", List.of(invalid));
      IllegalArgumentException listError =
          assertThrows(IllegalArgumentException.class, () -> WireSchema.snapshot(inList));
      assertEquals(
          "unsupported schema value: " + invalid.getClass().getName(), listError.getMessage());
    }
  }

  @Test
  void apiCatalogAndBatchMethodShareUnifiedSnapshotValidation() {
    ApiMethod<Map<String, Object>, Object> badRequestMethod =
        methodWithSchemas("test.bad_req", Map.of("minimum", new AtomicInteger(0)), Map.of());
    IllegalArgumentException catalogReqError =
        assertThrows(
            IllegalArgumentException.class,
            () -> ApiCatalog.from("0.2.0", List.of(badRequestMethod)));
    assertEquals(
        "unsupported schema value: java.util.concurrent.atomic.AtomicInteger",
        catalogReqError.getMessage());

    ApiMethod<Map<String, Object>, Object> badResponseMethod =
        methodWithSchemas("test.bad_res", Map.of(), Map.of("maximum", new AtomicInteger(10)));
    IllegalArgumentException catalogResError =
        assertThrows(
            IllegalArgumentException.class,
            () -> ApiCatalog.from("0.2.0", List.of(badResponseMethod)));
    assertEquals(
        "unsupported schema value: java.util.concurrent.atomic.AtomicInteger",
        catalogResError.getMessage());

    BatchMethod batchWithBadInput =
        new BatchMethod(Map.of("test.bad_req", badRequestMethod), inertBatchRuntime());
    IllegalArgumentException batchReqError =
        assertThrows(IllegalArgumentException.class, batchWithBadInput::registration);
    assertEquals(
        "unsupported schema value: java.util.concurrent.atomic.AtomicInteger",
        batchReqError.getMessage());

    ApiMethod<Map<String, Object>, Object> validMethod =
        methodWithSchemas("test.ok", WireSchema.object(Map.of()), WireSchema.object(Map.of()));
    BatchMethod.Registration validRegistration =
        new BatchMethod(Map.of("test.ok", validMethod), inertBatchRuntime()).registration();
    IllegalArgumentException batchResError =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                new BatchMethod.Registration(
                    validRegistration.effects(),
                    validRegistration.requestCodec(),
                    Map.of("bad", new AtomicInteger(5)),
                    validRegistration.handler()));
    assertEquals(
        "unsupported schema value: java.util.concurrent.atomic.AtomicInteger",
        batchResError.getMessage());
  }

  @Test
  void batchExecuteRequestCodecReturnsCachedPublishedSchemaReference() {
    ApiMethod<Map<String, Object>, Object> readMethod =
        methodWithSchemas(
            "demo.read",
            WireSchema.object(Map.of("name", WireSchema.nonBlankString()), "name"),
            WireSchema.object(Map.of("ok", WireSchema.bool()), "ok"));
    BatchMethod batch = new BatchMethod(Map.of("demo.read", readMethod), inertBatchRuntime());
    JsonCodec<Map<String, Object>> codec = batch.registration().requestCodec();

    Map<String, Object> first = codec.schema();
    Map<String, Object> second = codec.schema();
    assertSame(first, second);
    assertThrows(UnsupportedOperationException.class, () -> first.put("mutated", true));

    ApiRegistry registry =
        new ApiRegistry(
            inertServices(), "session", Map::of, () -> {});
    JsonCodec<Map<String, Object>> registeredBatchCodec =
        registry.method(BatchMethod.NAME).requestCodec();
    Map<String, Object> registeredFirst = registeredBatchCodec.schema();
    Map<String, Object> registeredSecond = registeredBatchCodec.schema();
    assertSame(registeredFirst, registeredSecond);
  }

  @Test
  void wirePublicSurfaceAndAll112CatalogSchemasPreserveStructureKeyOrderAndJson() throws Exception {
    Method snapshotMethod = WireSchema.class.getDeclaredMethod("snapshot", Map.class);
    assertFalse(Modifier.isPublic(snapshotMethod.getModifiers()));
    assertFalse(Modifier.isProtected(snapshotMethod.getModifiers()));
    assertFalse(Modifier.isPrivate(snapshotMethod.getModifiers()));

    List<String> jsonUtilPublicMethods =
        Arrays.stream(JsonUtil.class.getDeclaredMethods())
            .filter(method -> Modifier.isPublic(method.getModifiers()))
            .map(Method::getName)
            .sorted()
            .toList();
    assertEquals(List.of("parse", "parseObject", "toJson"), jsonUtilPublicMethods);

    ApiRegistry registry = new ApiRegistry(inertServices(), "schema", Map::of, () -> {});
    ApiCatalog catalog = registry.methodCatalog();
    assertEquals(56, catalog.methods().size());

    int verifiedSchemas = 0;
    for (ApiCatalog.MethodDescriptor descriptor : catalog.methods()) {
      ApiMethod<Map<String, Object>, Object> method = registry.method(descriptor.name());
      Map<String, Object> rawInput = method.requestCodec().schema();
      Map<String, Object> snapInput = descriptor.inputSchema();
      assertEquals(rawInput, snapInput);
      assertExactKeyOrder(rawInput, snapInput);
      assertEquals(JsonUtil.toJson(rawInput), JsonUtil.toJson(snapInput));
      verifiedSchemas++;

      Map<String, Object> rawOutput = method.responseCodec().schema();
      Map<String, Object> snapOutput = descriptor.outputSchema();
      assertEquals(rawOutput, snapOutput);
      assertExactKeyOrder(rawOutput, snapOutput);
      assertEquals(JsonUtil.toJson(rawOutput), JsonUtil.toJson(snapOutput));
      verifiedSchemas++;
    }
    assertEquals(112, verifiedSchemas);
  }

  private static void assertExactKeyOrder(Object expected, Object actual) {
    if (expected instanceof Map<?, ?> expectedMap && actual instanceof Map<?, ?> actualMap) {
      assertEquals(List.copyOf(expectedMap.keySet()), List.copyOf(actualMap.keySet()));
      for (Object key : expectedMap.keySet()) {
        assertExactKeyOrder(expectedMap.get(key), actualMap.get(key));
      }
    } else if (expected instanceof List<?> expectedList && actual instanceof List<?> actualList) {
      assertEquals(expectedList.size(), actualList.size());
      for (int i = 0; i < expectedList.size(); i++) {
        assertExactKeyOrder(expectedList.get(i), actualList.get(i));
      }
    }
  }

  private static ApiMethod<Map<String, Object>, Object> methodWithSchemas(
      String name, Map<String, Object> reqSchema, Map<String, Object> resSchema) {
    MethodEffects effects = MethodEffects.readOnlyMethod();
    JsonCodec<Map<String, Object>> reqCodec =
        new JsonCodec<>() {
          @Override
          public Map<String, Object> decode(Object value, String target) {
            return Map.of();
          }

          @Override
          public Object encode(Map<String, Object> value) {
            return value;
          }

          @Override
          public Map<String, Object> schema() {
            return reqSchema;
          }
        };
    JsonCodec<Object> resCodec =
        new JsonCodec<>() {
          @Override
          public Object decode(Object value, String target) {
            return value;
          }

          @Override
          public Object encode(Object value) {
            return value;
          }

          @Override
          public Map<String, Object> schema() {
            return resSchema;
          }
        };
    return new ApiMethod<>(
        name,
        "Test method " + name,
        effects,
        reqCodec,
        resCodec,
        Set.of(),
        List.of(),
        request -> Map.of(),
        McpAnnotations.forMethod(name, effects));
  }

  private static BatchMethod.BatchRuntime inertBatchRuntime() {
    return new BatchMethod.BatchRuntime() {
      @Override
      public Object invokeDecoded(
          ApiMethod<Map<String, Object>, Object> method,
          Map<String, Object> request,
          boolean ownTransaction) {
        throw new UnsupportedOperationException();
      }

      @Override
      public <T> T inTransaction(TransactionRunner.Operation<T> operation) {
        throw new UnsupportedOperationException();
      }
    };
  }

  private static app.byteland.ghidra.service.BridgeServices inertServices() {
    return new app.byteland.ghidra.service.BridgeServices(
        proxy(app.byteland.ghidra.service.program.ProgramService.class),
        proxy(app.byteland.ghidra.service.address.AddressService.class),
        proxy(app.byteland.ghidra.service.comment.CommentService.class),
        proxy(app.byteland.ghidra.service.reference.ReferenceService.class),
        proxy(app.byteland.ghidra.service.memory.MemoryService.class),
        proxy(app.byteland.ghidra.service.listing.ListingService.class),
        proxy(app.byteland.ghidra.service.function.FunctionService.class),
        proxy(app.byteland.ghidra.service.globalvariable.GlobalVariableService.class),
        proxy(app.byteland.ghidra.service.analysis.AnalysisService.class),
        proxy(app.byteland.ghidra.service.decompilation.DecompilationService.class),
        proxy(app.byteland.ghidra.service.symbol.SymbolService.class),
        proxy(app.byteland.ghidra.service.datatype.DataTypeService.class),
        proxy(TransactionRunner.class),
        "test");
  }

  private static <T> T proxy(Class<T> type) {
    return type.cast(
        java.lang.reflect.Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (proxy, method, args) -> {
              throw new UnsupportedOperationException(method.getName());
            }));
  }
}
