package app.byteland.ghidra;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.AbstractMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class JsonUtilTest {

  @Test
  void rawJsonRejectsNullInput() {
    assertThrows(NullPointerException.class, () -> JsonUtil.rawJson(null));
  }

  @Test
  void rawJsonAppendsDirectlyAcrossContainersWithoutQuotesOrEscaping() {
    String preSerialized = "{\"operation\":\"read\",\"bytes\":\"7f454c46\",\"count\":4}";

    assertEquals(preSerialized, JsonUtil.toJson(JsonUtil.rawJson(preSerialized)));

    Map<String, Object> withRaw = new LinkedHashMap<>();
    withRaw.put("text", preSerialized);
    withRaw.put("structuredContent", JsonUtil.rawJson(preSerialized));

    Map<String, Object> withMap = new LinkedHashMap<>();
    withMap.put("text", preSerialized);
    Map<String, Object> nested = new LinkedHashMap<>();
    nested.put("operation", "read");
    nested.put("bytes", "7f454c46");
    nested.put("count", 4);
    withMap.put("structuredContent", nested);

    assertEquals(JsonUtil.toJson(withMap), JsonUtil.toJson(withRaw));

    assertEquals(
        "[true,null,42,{\"k\":\"v\"},[1,2]]",
        JsonUtil.toJson(
            List.of(
                JsonUtil.rawJson("true"),
                JsonUtil.rawJson("null"),
                JsonUtil.rawJson("42"),
                JsonUtil.rawJson("{\"k\":\"v\"}"),
                JsonUtil.rawJson("[1,2]"))));

    assertEquals(
        "[{\"a\":1},false]",
        JsonUtil.toJson(new Object[] {JsonUtil.rawJson("{\"a\":1}"), JsonUtil.rawJson("false")}));
  }

  @Test
  void rawJsonPreservesSpecialCharactersAndPrimitivesByteForByte() {
    Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("message", "quote:\" slash:\\ newline:\n tab:\t ctrl:\u0001 unicode:処理/🚀");
    payload.put("non_finite", Double.NaN);
    payload.put("infinite", Float.POSITIVE_INFINITY);
    payload.put("empty", null);
    payload.put("items", List.of(1, true, "two"));

    String innerJson = JsonUtil.toJson(payload);

    Map<String, Object> expectedEnvelope = new LinkedHashMap<>();
    expectedEnvelope.put("content", List.of(Map.of("type", "text", "text", innerJson)));
    expectedEnvelope.put("structuredContent", payload);

    Map<String, Object> actualEnvelope = new LinkedHashMap<>();
    actualEnvelope.put("content", List.of(Map.of("type", "text", "text", innerJson)));
    actualEnvelope.put("structuredContent", JsonUtil.rawJson(innerJson));

    assertEquals(JsonUtil.toJson(expectedEnvelope), JsonUtil.toJson(actualEnvelope));
  }

  @Test
  void rawJsonTraversesUnderlyingMapOnlyOnce() {
    AtomicInteger traversals = new AtomicInteger();
    Map<String, Object> backing = new LinkedHashMap<>();
    backing.put("entry", "ram:00100000");
    backing.put("name", "main");
    Map<String, Object> countingMap =
        new AbstractMap<>() {
          @Override
          public Set<Entry<String, Object>> entrySet() {
            traversals.incrementAndGet();
            return backing.entrySet();
          }
        };

    String innerJson = JsonUtil.toJson(countingMap);
    assertEquals(1, traversals.get());

    Map<String, Object> envelope = new LinkedHashMap<>();
    envelope.put("text", innerJson);
    envelope.put("structuredContent", JsonUtil.rawJson(innerJson));
    String wire = JsonUtil.toJson(envelope);

    assertEquals(1, traversals.get());
    assertEquals(
        Map.of("entry", "ram:00100000", "name", "main"),
        JsonUtil.parseObject(wire).get("structuredContent"));
  }

  @Test
  void toJsonEnforcesMaximumNestingDepth() {
    Map<String, Object> depth500 = nestedMaps(500);
    String valid = JsonUtil.toJson(depth500);
    assertEquals(depth500, JsonUtil.parse(valid));

    Map<String, Object> depth501 = nestedMaps(501);
    assertThrows(IllegalArgumentException.class, () -> JsonUtil.toJson(depth501));
  }

  private static Map<String, Object> nestedMaps(int depth) {
    Map<String, Object> current = Map.of();
    for (int i = 1; i < depth; i++) {
      current = Map.of("n", current);
    }
    return current;
  }
}
