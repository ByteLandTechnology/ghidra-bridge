package app.byteland.ghidra;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.api.CursorTokens;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;

class JsonUtilCanonicalTest {
  @Test
  void canonicalSortsNestedMapsWithStringValueOfAndPreservesNullValues() {
    Map<Object, Object> inner = new LinkedHashMap<>();
    inner.put("z", 1);
    inner.put(2, "two");
    inner.put("a", null);
    inner.put(null, true);

    Map<Object, Object> outer = new HashMap<>();
    outer.put("omega", inner);
    outer.put("alpha", "first");
    outer.put("nullable", null);

    Object result = JsonUtil.canonical(outer);
    TreeMap<?, ?> canonicalOuter = assertInstanceOf(TreeMap.class, result);
    assertEquals(List.of("alpha", "nullable", "omega"), List.copyOf(canonicalOuter.keySet()));
    assertTrue(canonicalOuter.containsKey("nullable"));
    assertNull(canonicalOuter.get("nullable"));

    TreeMap<?, ?> canonicalInner = assertInstanceOf(TreeMap.class, canonicalOuter.get("omega"));
    assertEquals(List.of("2", "a", "null", "z"), List.copyOf(canonicalInner.keySet()));
    assertEquals("two", canonicalInner.get("2"));
    assertTrue(canonicalInner.containsKey("a"));
    assertNull(canonicalInner.get("a"));
    assertEquals(true, canonicalInner.get("null"));
    assertEquals(1, canonicalInner.get("z"));
    assertNull(JsonUtil.canonical(null));
  }

  @Test
  void canonicalConvertsSetsAndNullContainingListsIntoArrayLists() {
    Map<String, Object> secondFirst = new LinkedHashMap<>();
    secondFirst.put("b", 2);
    secondFirst.put("a", 1);

    Set<Object> orderedSet = new LinkedHashSet<>();
    orderedSet.add(secondFirst);
    orderedSet.add(null);
    orderedSet.add("tail");

    List<Object> listWithNulls = Arrays.asList("head", null, orderedSet, null);
    Iterable<Object> customIterable = listWithNulls::iterator;

    ArrayList<?> canonicalList = assertInstanceOf(ArrayList.class, JsonUtil.canonical(customIterable));
    assertEquals(4, canonicalList.size());
    assertEquals("head", canonicalList.get(0));
    assertNull(canonicalList.get(1));
    assertNull(canonicalList.get(3));

    ArrayList<?> canonicalSet = assertInstanceOf(ArrayList.class, canonicalList.get(2));
    assertEquals(3, canonicalSet.size());
    TreeMap<?, ?> nestedMap = assertInstanceOf(TreeMap.class, canonicalSet.get(0));
    assertEquals(List.of("a", "b"), List.copyOf(nestedMap.keySet()));
    assertNull(canonicalSet.get(1));
    assertEquals("tail", canonicalSet.get(2));
  }

  @Test
  void queryFingerprintMatchesExpectedDigestAcrossInsertionOrdersAndIterables() throws Exception {
    Map<String, Object> filterA = new LinkedHashMap<>();
    filterA.put("name_prefix", "sub_");
    filterA.put("tags", new LinkedHashSet<>(Arrays.asList("entry", null, "thunk")));

    Map<String, Object> requestA = new LinkedHashMap<>();
    requestA.put("range", Map.of("end", "ram:00402000", "start", "ram:00401000"));
    requestA.put("filter", filterA);
    requestA.put("cursor", "ignored-cursor");
    requestA.put("fields", List.of("name"));
    requestA.put("limit", 25);
    requestA.put("timeout_ms", 500);

    Map<String, Object> filterB = new LinkedHashMap<>();
    filterB.put("tags", Arrays.asList("entry", null, "thunk"));
    filterB.put("name_prefix", "sub_");

    Map<String, Object> rangeB = new LinkedHashMap<>();
    rangeB.put("start", "ram:00401000");
    rangeB.put("end", "ram:00402000");

    Map<String, Object> requestB = new LinkedHashMap<>();
    requestB.put("filter", filterB);
    requestB.put("range", rangeB);
    requestB.put("limit", 100);

    String fingerprintA = CursorTokens.queryFingerprint(requestA);
    String fingerprintB = CursorTokens.queryFingerprint(requestB);
    assertEquals(fingerprintA, fingerprintB);

    String expectedJson =
        "{\"filter\":{\"name_prefix\":\"sub_\",\"tags\":[\"entry\",null,\"thunk\"]},"
            + "\"range\":{\"end\":\"ram:00402000\",\"start\":\"ram:00401000\"}}";
    String expectedDigest =
        Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(
                MessageDigest.getInstance("SHA-256")
                    .digest(expectedJson.getBytes(StandardCharsets.UTF_8)));
    assertEquals(expectedDigest, fingerprintA);

    assertEquals(
        CursorTokens.queryFingerprint(Map.of()),
        CursorTokens.queryFingerprint(Map.of("filter", Map.of(), "limit", 10)));
    assertNotEquals(
        fingerprintA,
        CursorTokens.queryFingerprint(
            Map.of("range", Map.of("start", "ram:00401000", "end", "ram:00403000"))));
  }
}
