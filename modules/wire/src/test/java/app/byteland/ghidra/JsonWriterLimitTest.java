package app.byteland.ghidra;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import app.byteland.ghidra.api.ApiException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;

class JsonWriterLimitTest {

  @Test
  void stringLengthAndUtf8StreamMatchAcrossAllCharacterClasses() throws IOException {
    Map<String, Object> payload = new LinkedHashMap<>();
    payload.put("ascii", "hello \"world\" \\ \b\f\n\r\t");
    payload.put("controls", "\u0000\u0001\u001f");
    payload.put("two_byte", "\u0080\u00e9\u07ff");
    payload.put("three_byte", "\u0800中文日本語\uffff");
    payload.put("surrogate_pair", "rocket=\ud83d\ude80 boom=\ud83d\udca5");
    payload.put("unpaired_high", "pre\ud800post");
    payload.put("unpaired_low", "pre\udc00post");
    payload.put("unpaired_end", "tail\ud83d");
    payload.put(
        "numbers",
        List.of(0, -42, Long.MAX_VALUE, 3.5, Double.NaN, Double.POSITIVE_INFINITY, true, false));
    payload.put("array", new int[] {1, 2, 3});
    payload.put("null_value", null);
    payload.put(
        "raw_nested",
        JsonUtil.rawJson(
            JsonUtil.toJson(
                Map.of(
                    "unicode",
                    "処理/\u00e9/\ud83d\ude80",
                    "unpaired",
                    "pre\ud800post",
                    "escaped",
                    "\"\\\n\u0001"))));
    // Span multiple 8 KiB stream buffer flushes with multi-byte characters across boundaries.
    payload.put("large_mixed", ("ab\"\\\n\u00e9漢\ud83d\ude80").repeat(2000));

    String json = JsonUtil.toJson(payload);
    byte[] expectedUtf8 = json.getBytes(StandardCharsets.UTF_8);

    int countedLength = JsonUtil.utf8ByteLength(payload, expectedUtf8.length);
    assertEquals(expectedUtf8.length, countedLength);

    ByteArrayOutputStream streamed = new ByteArrayOutputStream();
    JsonUtil.writeUtf8(payload, streamed, expectedUtf8.length);
    assertArrayEquals(expectedUtf8, streamed.toByteArray());
  }

  @Test
  void enforcesExactMaxUtf8ByteLimitAcrossAllSinks() throws IOException {
    Map<String, Object> value = Map.of("key", "value-\u00e9-漢-\ud83d\ude80");
    int exactBytes = JsonUtil.toJson(value).getBytes(StandardCharsets.UTF_8).length;

    assertEquals(exactBytes, JsonUtil.utf8ByteLength(value, exactBytes));
    assertEquals(
        exactBytes, JsonUtil.toJson(value, exactBytes).getBytes(StandardCharsets.UTF_8).length);
    ByteArrayOutputStream okOut = new ByteArrayOutputStream();
    JsonUtil.writeUtf8(value, okOut, exactBytes);
    assertEquals(exactBytes, okOut.size());

    int oneByteShort = exactBytes - 1;
    ApiException countError =
        assertThrows(ApiException.class, () -> JsonUtil.utf8ByteLength(value, oneByteShort));
    assertEquals(413, countError.status());
    assertEquals("response_too_large", countError.error().code());

    ApiException stringError =
        assertThrows(ApiException.class, () -> JsonUtil.toJson(value, oneByteShort));
    assertEquals(413, stringError.status());
    assertEquals("response_too_large", stringError.error().code());

    ByteArrayOutputStream limitedOut = new ByteArrayOutputStream();
    ApiException streamError =
        assertThrows(
            ApiException.class, () -> JsonUtil.writeUtf8(value, limitedOut, oneByteShort));
    assertEquals(413, streamError.status());
    assertEquals("response_too_large", streamError.error().code());

    assertThrows(IllegalArgumentException.class, () -> JsonUtil.toJson("x", -1));
    assertThrows(IllegalArgumentException.class, () -> JsonUtil.utf8ByteLength("x", -1));
    assertThrows(
        IllegalArgumentException.class,
        () -> JsonUtil.writeUtf8("x", new ByteArrayOutputStream(), -1));
  }

  @Test
  void preservesRawJsonIdentityWithinLimitAndConsumesSinglePassIterableOnce() throws IOException {
    String rawText = "{\"hex\":\"" + "ab".repeat(32_768) + "\",\"note\":\"漢字\"}";
    Object raw = JsonUtil.rawJson(rawText);
    int rawUtf8Bytes = rawText.getBytes(StandardCharsets.UTF_8).length;

    assertSame(rawText, JsonUtil.toJson(raw, rawUtf8Bytes));
    ApiException rawOverflow =
        assertThrows(ApiException.class, () -> JsonUtil.toJson(raw, rawUtf8Bytes - 1));
    assertEquals(413, rawOverflow.status());
    assertEquals("response_too_large", rawOverflow.error().code());

    ByteArrayOutputStream partialStream = new ByteArrayOutputStream();
    assertThrows(
        ApiException.class, () -> JsonUtil.writeUtf8(raw, partialStream, rawUtf8Bytes - 1));
    assertEquals(true, partialStream.size() <= rawUtf8Bytes - 1);

    String pureAsciiRaw = "{\"hex\":\"" + "ab".repeat(32_768) + "\"}";
    ByteArrayOutputStream zeroByteStream = new ByteArrayOutputStream();
    assertThrows(
        ApiException.class,
        () -> JsonUtil.writeUtf8(JsonUtil.rawJson(pureAsciiRaw), zeroByteStream, pureAsciiRaw.length() - 1));
    assertEquals(0, zeroByteStream.size());

    AtomicBoolean consumed = new AtomicBoolean(false);
    Iterable<String> singlePass =
        () -> {
          if (!consumed.compareAndSet(false, true)) {
            throw new IllegalStateException("single-pass iterable consumed more than once");
          }
          Iterator<String> delegate = List.of("alpha", "beta", "gamma").iterator();
          return delegate;
        };
    assertEquals("{\"items\":[\"alpha\",\"beta\",\"gamma\"]}", JsonUtil.toJson(Map.of("items", singlePass)));
  }
}
