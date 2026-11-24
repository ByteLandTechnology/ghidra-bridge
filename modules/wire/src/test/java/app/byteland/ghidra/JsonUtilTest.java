package app.byteland.ghidra;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import app.byteland.ghidra.api.CursorTokens;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class JsonUtilTest {

  @Test
  void unescapedSlicesRoundTripIncludingEmptyAndLargePayloads() {
    assertEquals("\"\"", JsonUtil.toJson(""));
    assertEquals("", JsonUtil.parse("\"\""));

    assertEquals("\"ram:00101000\"", JsonUtil.toJson("ram:00101000"));
    assertEquals("ram:00101000", JsonUtil.parse("\"ram:00101000\""));

    String hex64KiB = "deadbeef01234567".repeat(8192);
    Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("address", "ram:00100000");
    payload.put("bytes", Map.of("encoding", "hex", "data", hex64KiB, "length", 65536));

    String json = JsonUtil.toJson(payload);
    assertTrue(
        JsonWriter.estimateInitialCapacity(payload) >= json.length(),
        "Pre-sized root buffer should cover 64 KiB hex payload without growth");
    assertEquals(payload, JsonUtil.parseObject(json));

    Map<String, Object> mcpEnvelope = new LinkedHashMap<>();
    mcpEnvelope.put("content", List.of(Map.of("type", "text", "text", json)));
    mcpEnvelope.put("structuredContent", JsonUtil.rawJson(json));
    String envelopeJson = JsonUtil.toJson(mcpEnvelope);
    assertTrue(
        JsonWriter.estimateInitialCapacity(mcpEnvelope) >= envelopeJson.length(),
        "Pre-sized root buffer should cover MCP RawJson envelope without growth");
  }

  @Test
  void preSizesRootBufferForFiveThousandTokenPayload() {
    List<Map<String, Object>> lines = new ArrayList<>(500);
    for (int lineIdx = 0; lineIdx < 500; lineIdx++) {
      List<Map<String, Object>> tokens = new ArrayList<>(10);
      for (int tokIdx = 0; tokIdx < 10; tokIdx++) {
        Map<String, Object> token = new LinkedHashMap<>();
        token.put("kind", "identifier");
        token.put("text", "param_" + tokIdx);
        token.put("start", tokIdx * 8);
        token.put("end", tokIdx * 8 + 7);
        token.put("location_address", "ram:00101000");
        tokens.add(token);
      }
      Map<String, Object> line = new LinkedHashMap<>();
      line.put("number", lineIdx);
      line.put("indent", 2);
      line.put("tokens", tokens);
      lines.add(line);
    }
    Map<String, Object> document = new LinkedHashMap<>();
    document.put("format", "document");
    document.put("c", "int main(void) {\n  return 0;\n}\n".repeat(200));
    document.put("lines", lines);

    String json = JsonUtil.toJson(document);
    assertTrue(
        JsonWriter.estimateInitialCapacity(document) >= json.length(),
        "Pre-sized root buffer should cover 5,000-token payload without growth");
    assertEquals(document, JsonUtil.parseObject(json));
  }

  @Test
  void leadingTrailingAndAdjacentEscapesAdvanceRunSlicesCleanly() {
    String leading = "\nhello";
    assertEquals("\"\\nhello\"", JsonUtil.toJson(leading));
    assertEquals(leading, JsonUtil.parse("\"\\nhello\""));

    String trailing = "hello\t";
    assertEquals("\"hello\\t\"", JsonUtil.toJson(trailing));
    assertEquals(trailing, JsonUtil.parse("\"hello\\t\""));

    String adjacent = "\"\\\b\f\n\r\t";
    assertEquals("\"\\\"\\\\\\b\\f\\n\\r\\t\"", JsonUtil.toJson(adjacent));
    assertEquals(adjacent, JsonUtil.parse("\"\\\"\\\\\\b\\f\\n\\r\\t\""));

    // Forward slash escape is optional in JSON output, but required to decode in parser.
    assertEquals("a/b\\c\"d", JsonUtil.parse("\"a\\/b\\\\c\\\"d\""));
    assertEquals("\u0000\u001f", JsonUtil.parse("\"\\u0000\\u001F\""));

    Map<String, Object> escapedKeys = new LinkedHashMap<>();
    escapedKeys.put("\"key\\1\n\"", "val\r\n\"end\\");
    String encoded = JsonUtil.toJson(escapedKeys);
    assertEquals("{\"\\\"key\\\\1\\n\\\"\":\"val\\r\\n\\\"end\\\\\"}", encoded);
    assertEquals(escapedKeys, JsonUtil.parseObject(encoded));
  }

  @Test
  void controlCharactersZeroToOneFSerializeAsLowercaseHexAndRejectUnescapedControls() {
    for (int code = 0x00; code <= 0x1f; code++) {
      char ch = (char) code;
      String value = "prefix" + ch + "suffix";
      String expectedJson =
          switch (ch) {
            case '\b' -> "\"prefix\\bsuffix\"";
            case '\t' -> "\"prefix\\tsuffix\"";
            case '\n' -> "\"prefix\\nsuffix\"";
            case '\f' -> "\"prefix\\fsuffix\"";
            case '\r' -> "\"prefix\\rsuffix\"";
            default -> String.format(Locale.ROOT, "\"prefix\\u%04xsuffix\"", code);
          };
      String actualJson = JsonUtil.toJson(value);
      assertEquals(expectedJson, actualJson);
      assertEquals(value, JsonUtil.parse(actualJson));

      // Unescaped fast path must reject raw control character.
      String rawUnescaped = "\"prefix" + ch + "suffix\"";
      IllegalArgumentException fastError =
          assertThrows(IllegalArgumentException.class, () -> JsonUtil.parse(rawUnescaped));
      assertEquals("Unescaped control character in string", fastError.getMessage());

      // Lazy StringBuilder path (after a valid escape) must also reject raw control character.
      String rawAfterEscape = "\"\\nprefix" + ch + "suffix\"";
      IllegalArgumentException lazyError =
          assertThrows(IllegalArgumentException.class, () -> JsonUtil.parse(rawAfterEscape));
      assertEquals("Unescaped control character in string", lazyError.getMessage());
    }
  }

  @Test
  void unicodeSurrogatesAndSupplementaryCharactersRoundTrip() {
    String literal = "事务失败 / 処理失敗 💥🚀 \"quoted\" \uD834\uDD1E";
    String encoded = JsonUtil.toJson(literal);
    assertEquals(literal, JsonUtil.parse(encoded));

    String unicodeEscaped = "\"\\ud83d\\udca5\\uD834\\uDD1E\\u4e8b\\u52a1\"";
    assertEquals("💥𝄞事务", JsonUtil.parse(unicodeEscaped));
  }

  @Test
  void invalidEscapesAndUnterminatedStringsThrowIllegalArgumentException() {
    assertThrows(IllegalArgumentException.class, () -> JsonUtil.parse("\"unterminated"));
    assertThrows(IllegalArgumentException.class, () -> JsonUtil.parse("\"\\n_unterminated"));
    assertThrows(IllegalArgumentException.class, () -> JsonUtil.parse("\"trailing_backslash\\"));
    assertThrows(IllegalArgumentException.class, () -> JsonUtil.parse("\"\\x\""));
    assertThrows(IllegalArgumentException.class, () -> JsonUtil.parse("\"\\a\""));
    assertThrows(IllegalArgumentException.class, () -> JsonUtil.parse("\"\\u\""));
    assertThrows(IllegalArgumentException.class, () -> JsonUtil.parse("\"\\u12\""));
    assertThrows(IllegalArgumentException.class, () -> JsonUtil.parse("\"\\u123g\""));
    assertThrows(IllegalArgumentException.class, () -> JsonUtil.parse("\"\\u+001\""));
    assertThrows(IllegalArgumentException.class, () -> JsonUtil.parse("\"\\u-001\""));
  }

  @Test
  void arraysSetsFallbackValuesAndInvalidMapKeysPreserveSemantics() {
    Set<String> tags = new LinkedHashSet<>(List.of("alpha", "beta"));
    Map<String, Object> composite = new LinkedHashMap<>();
    composite.put("ints", new int[] {1, 2, 3});
    composite.put("strings", new String[] {"a\"b", "c\\d"});
    composite.put("tags", tags);
    composite.put("nonFinite", Double.NaN);

    String json = JsonUtil.toJson(composite);
    assertEquals(
        "{\"ints\":[1,2,3],\"strings\":[\"a\\\"b\",\"c\\\\d\"],\"tags\":[\"alpha\",\"beta\"],\"nonFinite\":null}",
        json);

    Map<Object, Object> badMap = new LinkedHashMap<>();
    badMap.put(42, "value");
    assertThrows(IllegalArgumentException.class, () -> JsonUtil.toJson(badMap));

    // Single-pass Iterable must not be consumed during capacity estimation.
    Iterator<String> iterator = List.of("one", "two").iterator();
    Iterable<String> singlePass = () -> iterator;
    assertEquals("[\"one\",\"two\"]", JsonUtil.toJson(singlePass));
  }

  @Test
  void nestingDepthLimitAndCursorFingerprintRemainUnchanged() throws Exception {
    Object deep = "leaf";
    for (int i = 0; i < 501; i++) {
      deep = List.of(deep);
    }
    Object tooDeep = deep;
    assertThrows(IllegalArgumentException.class, () -> JsonUtil.toJson(tooDeep));
    assertThrows(
        IllegalArgumentException.class,
        () -> JsonUtil.parse("[".repeat(501) + "1" + "]".repeat(501)));

    Map<String, Object> query = new LinkedHashMap<>();
    query.put("selector", Map.of("address", "ram:00101000"));
    query.put("filter", Map.of("name", "FUN_00101000", "namespace", "std::vector"));
    String expectedCanonicalJson =
        "{\"filter\":{\"name\":\"FUN_00101000\",\"namespace\":\"std::vector\"},\"selector\":{\"address\":\"ram:00101000\"}}";
    String expectedFingerprint =
        Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(
                MessageDigest.getInstance("SHA-256")
                    .digest(expectedCanonicalJson.getBytes(StandardCharsets.UTF_8)));
    assertEquals(expectedFingerprint, CursorTokens.queryFingerprint(query));
  }

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
