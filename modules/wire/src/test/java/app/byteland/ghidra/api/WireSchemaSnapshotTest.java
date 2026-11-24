package app.byteland.ghidra.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.service.BridgeServices;
import app.byteland.ghidra.service.TransactionRunner;
import app.byteland.ghidra.service.address.AddressService;
import app.byteland.ghidra.service.analysis.AnalysisService;
import app.byteland.ghidra.service.comment.CommentService;
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
import java.math.BigDecimal;
import java.math.BigInteger;
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
import org.junit.jupiter.api.Test;

class WireSchemaSnapshotTest {
  @Test
  void snapshotAcceptsEightImmutableNumberTypesAndPreservesNulls() {
    List<Object> mutableList =
        new ArrayList<>(
            Arrays.asList(
                null,
                "text",
                true,
                (byte) 1,
                (short) 2,
                3,
                4L,
                5.5f,
                6.25d,
                BigInteger.valueOf(7),
                new BigDecimal("8.75")));
    Map<String, Object> nested = new LinkedHashMap<>();
    nested.put("nullable_default", null);
    nested.put("numbers", mutableList);

    Map<String, Object> source = new LinkedHashMap<>();
    source.put("type", "object");
    source.put("byte", (byte) 10);
    source.put("short", (short) 20);
    source.put("integer", 30);
    source.put("long", 40L);
    source.put("float", 50.5f);
    source.put("double", 60.25d);
    source.put("big_integer", new BigInteger("70000000000000000000"));
    source.put("big_decimal", new BigDecimal("80.125"));
    source.put("null_value", null);
    source.put("nested", nested);

    Map<String, Object> frozen = WireSchema.snapshot(source);

    source.put("mutated", "after");
    nested.put("extra", 99);
    mutableList.add("mutated");

    assertFalse(frozen.containsKey("mutated"));
    assertEquals(
        List.of(
            "type",
            "byte",
            "short",
            "integer",
            "long",
            "float",
            "double",
            "big_integer",
            "big_decimal",
            "null_value",
            "nested"),
        List.copyOf(frozen.keySet()));
    assertTrue(frozen.containsKey("null_value"));
    assertNull(frozen.get("null_value"));
    assertEquals((byte) 10, frozen.get("byte"));
    assertEquals((short) 20, frozen.get("short"));
    assertEquals(30, frozen.get("integer"));
    assertEquals(40L, frozen.get("long"));
    assertEquals(50.5f, frozen.get("float"));
    assertEquals(60.25d, frozen.get("double"));
    assertEquals(new BigInteger("70000000000000000000"), frozen.get("big_integer"));
    assertEquals(new BigDecimal("80.125"), frozen.get("big_decimal"));

    @SuppressWarnings("unchecked")
    Map<String, Object> frozenNested = (Map<String, Object>) frozen.get("nested");
    assertFalse(frozenNested.containsKey("extra"));
    assertTrue(frozenNested.containsKey("nullable_default"));
    assertNull(frozenNested.get("nullable_default"));

    @SuppressWarnings("unchecked")
    List<Object> frozenList = (List<Object>) frozenNested.get("numbers");
    assertEquals(11, frozenList.size());
    assertNull(frozenList.getFirst());
    assertEquals(new BigDecimal("8.75"), frozenList.getLast());

    assertThrows(UnsupportedOperationException.class, () -> frozen.put("x", 1));
    assertThrows(UnsupportedOperationException.class, () -> frozenNested.remove("numbers"));
    assertThrows(UnsupportedOperationException.class, () -> frozenList.add("x"));
  }

  @Test
  void snapshotRejectsMutableNumbersNonListCollectionsAndInvalidKeys() {
    assertThrows(NullPointerException.class, () -> WireSchema.snapshot(null));

    IllegalArgumentException atomicError =
        assertThrows(
            IllegalArgumentException.class,
            () -> WireSchema.snapshot(Map.of("minimum", new AtomicInteger(1))));
    assertTrue(atomicError.getMessage().contains("schema"));
    assertTrue(atomicError.getMessage().contains(AtomicInteger.class.getName()));
    assertFalse(atomicError.getMessage().contains("response"));

    IllegalArgumentException nestedAtomicError =
        assertThrows(
            IllegalArgumentException.class,
            () -> WireSchema.snapshot(Map.of("enum", List.of(new AtomicLong(2L)))));
    assertTrue(nestedAtomicError.getMessage().contains(AtomicLong.class.getName()));

    IllegalArgumentException setError =
        assertThrows(
            IllegalArgumentException.class,
            () -> WireSchema.snapshot(Map.of("enum", new LinkedHashSet<>(List.of("a", "b")))));
    assertTrue(setError.getMessage().contains("schema"));
    assertFalse(setError.getMessage().contains("response"));

    IllegalArgumentException immutableSetError =
        assertThrows(
            IllegalArgumentException.class,
            () -> WireSchema.snapshot(Map.of("required", Set.of("id"))));
    assertTrue(immutableSetError.getMessage().contains("schema"));

    IllegalArgumentException integerKeyError =
        assertThrows(IllegalArgumentException.class, () -> WireSchema.snapshot(Map.of(1, "value")));
    assertEquals("schema object keys must be strings", integerKeyError.getMessage());

    Map<Object, Object> nullKeyMap = new HashMap<>();
    nullKeyMap.put(null, "value");
    IllegalArgumentException nullKeyError =
        assertThrows(IllegalArgumentException.class, () -> WireSchema.snapshot(nullKeyMap));
    assertEquals("schema object keys must be strings", nullKeyError.getMessage());
  }

  @Test
  void apiCatalogEnforcesSnapshotRulesOnMethodSchemas() {
    ApiMethod<Map<String, Object>, Object> invalidMethod =
        customMethod(Map.of("minimum", new AtomicInteger(0)), Map.of("type", "object"));
    IllegalArgumentException error =
        assertThrows(
            IllegalArgumentException.class, () -> ApiCatalog.from("0.2.0", List.of(invalidMethod)));
    assertTrue(error.getMessage().contains(AtomicInteger.class.getName()));

    Map<String, Object> mutableSchema = new LinkedHashMap<>();
    mutableSchema.put("type", "object");
    mutableSchema.put("default", null);
    mutableSchema.put("examples", new ArrayList<>(Arrays.asList(null, 1, new BigDecimal("2.5"))));
    ApiMethod<Map<String, Object>, Object> validMethod =
        customMethod(mutableSchema, Map.of("type", "object"));

    ApiCatalog catalog = ApiCatalog.from("0.2.0", List.of(validMethod));
    mutableSchema.put("injected", true);
    Map<String, Object> inputSchema = catalog.methods().getFirst().inputSchema();
    assertFalse(inputSchema.containsKey("injected"));
    assertTrue(inputSchema.containsKey("default"));
    assertNull(inputSchema.get("default"));
    assertThrows(UnsupportedOperationException.class, () -> inputSchema.put("x", 1));
  }

  @Test
  void batchExecuteRequestCodecReturnsSameCachedSchemaReference() {
    ApiRegistry registry = new ApiRegistry(inertServices(), "test", Map::of, () -> {});
    ApiMethod<Map<String, Object>, Object> batch = registry.method(BatchMethod.NAME);
    assertNotNull(batch);

    Map<String, Object> first = batch.requestCodec().schema();
    Map<String, Object> second = batch.requestCodec().schema();
    assertSame(first, second);
    assertThrows(UnsupportedOperationException.class, () -> first.put("extra", true));

    @SuppressWarnings("unchecked")
    Map<String, Object> properties = (Map<String, Object>) first.get("properties");
    assertNotNull(properties);
    assertSame(properties, first.get("properties"));
    assertThrows(UnsupportedOperationException.class, () -> properties.put("extra", true));
  }

  private static ApiMethod<Map<String, Object>, Object> customMethod(
      Map<String, Object> requestSchema, Map<String, Object> responseSchema) {
    ApiMethod.MethodEffects effects = ApiMethod.MethodEffects.readOnlyMethod();
    JsonCodec<Map<String, Object>> requestCodec =
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
            return requestSchema;
          }
        };
    JsonCodec<Object> responseCodec =
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
            return responseSchema;
          }
        };
    return new ApiMethod<>(
        "custom.read",
        "Read custom test data.",
        effects,
        requestCodec,
        responseCodec,
        Set.of(),
        List.of(),
        request -> Map.of(),
        ApiMethod.McpAnnotations.forMethod("custom.read", effects));
  }

  private static BridgeServices inertServices() {
    return new BridgeServices(
        unused(ProgramService.class),
        unused(AddressService.class),
        unused(CommentService.class),
        unused(ReferenceService.class),
        unused(MemoryService.class),
        unused(ListingService.class),
        unused(FunctionService.class),
        unused(GlobalVariableService.class),
        unused(AnalysisService.class),
        unused(DecompilationService.class),
        unused(SymbolService.class),
        unused(DataTypeService.class),
        unused(TransactionRunner.class),
        "test");
  }

  private static <T> T unused(Class<T> type) {
    return type.cast(
        Proxy.newProxyInstance(
            type.getClassLoader(),
            new Class<?>[] {type},
            (proxy, method, args) -> {
              if (method.getDeclaringClass() == Object.class) {
                return switch (method.getName()) {
                  case "toString" -> "unused " + type.getSimpleName();
                  case "hashCode" -> System.identityHashCode(proxy);
                  case "equals" -> proxy == args[0];
                  default -> null;
                };
              }
              throw new AssertionError(method.getName());
            }));
  }
}
