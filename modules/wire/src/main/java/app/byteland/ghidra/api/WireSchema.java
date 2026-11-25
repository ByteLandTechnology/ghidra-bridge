package app.byteland.ghidra.api;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public final class WireSchema {
  private static final int EXACT_UNION_MATCHES = 1;

  private WireSchema() {}

  static Map<String, Object> snapshot(Map<?, ?> schema) {
    Objects.requireNonNull(schema, "schema");
    Map<String, Object> copy = new LinkedHashMap<>();
    for (Map.Entry<?, ?> entry : schema.entrySet()) {
      if (!(entry.getKey() instanceof String key)) {
        throw new IllegalArgumentException("schema object keys must be strings");
      }
      copy.put(key, snapshotValue(entry.getValue()));
    }
    return Collections.unmodifiableMap(copy);
  }

  private static Object snapshotValue(Object value) {
    if (value instanceof Map<?, ?> map) {
      return snapshot(map);
    }
    if (value instanceof List<?> list) {
      List<Object> copy = new ArrayList<>(list.size());
      for (Object item : list) {
        copy.add(snapshotValue(item));
      }
      return Collections.unmodifiableList(copy);
    }
    if (value == null
        || value instanceof String
        || value instanceof Boolean
        || value instanceof Byte
        || value instanceof Short
        || value instanceof Integer
        || value instanceof Long
        || value instanceof Float
        || value instanceof Double
        || value instanceof BigInteger
        || value instanceof BigDecimal) {
      return value;
    }
    throw new IllegalArgumentException("unsupported schema value: " + value.getClass().getName());
  }

  public static Map<String, Object> any() {
    return Map.of();
  }

  public static Map<String, Object> string() {
    return Map.of(ApiVocabulary.TYPE, ApiVocabulary.STRING);
  }

  public static Map<String, Object> nonBlankString() {
    return Map.of(ApiVocabulary.TYPE, ApiVocabulary.STRING, ApiVocabulary.MIN_LENGTH, 1);
  }

  public static Map<String, Object> stringEnum(String... values) {
    List<String> sorted = java.util.Arrays.stream(values).sorted().toList();
    return Map.of(ApiVocabulary.TYPE, ApiVocabulary.STRING, ApiVocabulary.ENUM, sorted);
  }

  public static Map<String, Object> bool() {
    return Map.of(ApiVocabulary.TYPE, ApiVocabulary.BOOLEAN);
  }

  public static Map<String, Object> integer(long minimum, long maximum) {
    return Map.of(
        ApiVocabulary.TYPE,
        ApiVocabulary.INTEGER,
        ApiVocabulary.MINIMUM,
        minimum,
        ApiVocabulary.MAXIMUM,
        maximum);
  }

  public static Map<String, Object> number(double minimum, double maximum) {
    return Map.of(
        ApiVocabulary.TYPE,
        ApiVocabulary.NUMBER,
        ApiVocabulary.MINIMUM,
        minimum,
        ApiVocabulary.MAXIMUM,
        maximum);
  }

  public static Map<String, Object> array(Map<String, Object> items, int minimum, int maximum) {
    return Map.of(
        ApiVocabulary.TYPE,
        ApiVocabulary.ARRAY,
        ApiVocabulary.ITEMS,
        items,
        ApiVocabulary.MIN_ITEMS,
        minimum,
        ApiVocabulary.MAX_ITEMS,
        maximum);
  }

  public static Map<String, Object> object(
      Map<String, Map<String, Object>> properties, String... required) {
    Map<String, Object> schema = new LinkedHashMap<>();
    schema.put(ApiVocabulary.TYPE, ApiVocabulary.OBJECT);
    schema.put(ApiVocabulary.ADDITIONAL_PROPERTIES, false);
    schema.put(ApiVocabulary.PROPERTIES, new LinkedHashMap<>(properties));
    if (required.length > 0) {
      schema.put(ApiVocabulary.REQUIRED, List.of(required));
    }
    return schema;
  }

  public static Map<String, Object> openObject() {
    return Map.of(
        ApiVocabulary.TYPE, ApiVocabulary.OBJECT, ApiVocabulary.ADDITIONAL_PROPERTIES, true);
  }

  public static Map<String, Object> bridgeError() {
    return object(
        Map.of(
            "status", integer(400, 599),
            "code", Map.of("type", "string", "pattern", "^[a-z][a-z0-9_]*$"),
            "message", nonBlankString(),
            "target", string(),
            "details", openObject()),
        "status",
        "code",
        "message");
  }

  public static Map<String, Object> nullable(Map<String, Object> schema) {
    return Map.of(
        ApiVocabulary.ONE_OF, List.of(schema, Map.of(ApiVocabulary.TYPE, ApiVocabulary.NULL)));
  }

  public static Map<String, Object> oneOf(List<Map<String, Object>> schemas) {
    return Map.of(ApiVocabulary.ONE_OF, List.copyOf(schemas));
  }

  public static Map<String, Object> oneOf(Map<String, Object> first, Map<String, Object> second) {
    return oneOf(List.of(first, second));
  }

  public static Map<String, Object> oneOf(
      Map<String, Object> first, Map<String, Object> second, Map<String, Object> third) {
    return oneOf(List.of(first, second, third));
  }

  public static Map<String, Object> oneOf(
      Map<String, Object> first,
      Map<String, Object> second,
      Map<String, Object> third,
      Map<String, Object> fourth) {
    return oneOf(List.of(first, second, third, fourth));
  }

  public static Map<String, Object> oneOf(
      Map<String, Object> first,
      Map<String, Object> second,
      Map<String, Object> third,
      Map<String, Object> fourth,
      Map<String, Object> fifth) {
    return oneOf(List.of(first, second, third, fourth, fifth));
  }

  public static Map<String, Object> dataTypeReference() {
    return Map.of(ApiVocabulary.REFERENCE, "#/$defs/data_type_reference");
  }

  public static Map<String, Object> withDefinitions(Map<String, Object> schema) {
    Map<String, Object> root = new LinkedHashMap<>(schema);
    root.put(ApiVocabulary.DEFINITIONS, DEFAULT_DEFINITIONS);
    return root;
  }

  private static final Map<String, Map<String, Object>> DEFAULT_DEFINITIONS =
      Map.of("data_type_reference", dataTypeReferenceDefinition());

  private static Map<String, Object> dataTypeReferenceDefinition() {
    Map<String, Object> named =
        object(
            Map.of(ApiVocabulary.KIND, stringEnum("named"), ApiVocabulary.NAME, nonBlankString()),
            ApiVocabulary.KIND,
            ApiVocabulary.NAME);
    Map<String, Object> pointer = new LinkedHashMap<>();
    pointer.put(ApiVocabulary.TYPE, ApiVocabulary.OBJECT);
    pointer.put(ApiVocabulary.ADDITIONAL_PROPERTIES, false);
    pointer.put(ApiVocabulary.REQUIRED, List.of(ApiVocabulary.KIND, "target"));
    Map<String, Object> pointerProperties = new LinkedHashMap<>();
    pointerProperties.put(ApiVocabulary.KIND, stringEnum("pointer"));
    pointerProperties.put("target", Map.of(ApiVocabulary.REFERENCE, "#/$defs/data_type_reference"));
    pointer.put(ApiVocabulary.PROPERTIES, pointerProperties);
    Map<String, Object> array = new LinkedHashMap<>();
    array.put(ApiVocabulary.TYPE, ApiVocabulary.OBJECT);
    array.put(ApiVocabulary.ADDITIONAL_PROPERTIES, false);
    array.put(ApiVocabulary.REQUIRED, List.of(ApiVocabulary.KIND, "element", "count"));
    Map<String, Object> arrayProperties = new LinkedHashMap<>();
    arrayProperties.put(ApiVocabulary.KIND, stringEnum(ApiVocabulary.ARRAY));
    arrayProperties.put("element", Map.of(ApiVocabulary.REFERENCE, "#/$defs/data_type_reference"));
    arrayProperties.put("count", integer(1, Integer.MAX_VALUE));
    array.put(ApiVocabulary.PROPERTIES, arrayProperties);
    Map<String, Object> untyped =
        object(Map.of(ApiVocabulary.KIND, stringEnum("untyped_pointer")), ApiVocabulary.KIND);
    return oneOf(named, pointer, array, untyped);
  }

  private static final Integer MAX_INT = Integer.MAX_VALUE;
  private static final Long MIN_LONG = Long.MIN_VALUE;
  private static final Long MAX_LONG = Long.MAX_VALUE;
  private static final Double MIN_DOUBLE = -Double.MAX_VALUE;
  private static final Double MAX_DOUBLE = Double.MAX_VALUE;

  public static void validate(Object value, Map<String, Object> schema, String target) {
    Map<String, Map<String, Object>> definitions = schemaDefinitions(schema);
    if (evaluate(value, schema, null, definitions) == null) {
      return;
    }
    ValidationFailure failure = evaluate(value, schema, new PointerCursor(target), definitions);
    throw ApiException.badRequest(failure.code(), failure.message(), failure.target());
  }

  @SuppressWarnings(ApiVocabulary.UNCHECKED)
  private static ValidationFailure evaluate(
      Object value,
      Map<String, Object> schema,
      PointerCursor cursor,
      Map<String, Map<String, Object>> definitions) {
    Object ref = schema.get(ApiVocabulary.REFERENCE);
    if (ref instanceof String reference && reference.startsWith("#/$defs/")) {
      return evaluate(value, resolveReference(reference, definitions), cursor, definitions);
    }
    if (schema.get(ApiVocabulary.ONE_OF) instanceof List<?> alternatives) {
      ValidationFailure firstFailure = null;
      int matchCount = 0;
      for (Object rawAlternative : alternatives) {
        Map<String, Object> alternative = (Map<String, Object>) rawAlternative;
        PointerCursor branchCursor = firstFailure == null ? cursor : null;
        ValidationFailure failure = evaluate(value, alternative, branchCursor, definitions);
        if (failure == null) {
          matchCount++;
        } else if (firstFailure == null) {
          firstFailure = failure;
        }
      }
      if (matchCount == EXACT_UNION_MATCHES) {
        return null;
      }
      if (cursor == null) {
        return ValidationFailure.PROBE_FAILURE;
      }
      if (firstFailure != null) {
        return new ValidationFailure(
            "invalid_union", firstFailure.message(), firstFailure.target());
      }
      return failure("invalid_union", cursor, " must match exactly one schema");
    }
    Object type = schema.get(ApiVocabulary.TYPE);
    if (type == null) {
      return null;
    }
    return switch (String.valueOf(type)) {
      case ApiVocabulary.NULL ->
          value == null ? null : failure(ApiVocabulary.INVALID_TYPE, cursor, " must be null");
      case ApiVocabulary.OBJECT -> evaluateObject(value, schema, cursor, definitions);
      case ApiVocabulary.ARRAY -> evaluateArray(value, schema, cursor, definitions);
      case ApiVocabulary.STRING -> evaluateString(value, schema, cursor);
      case ApiVocabulary.INTEGER -> evaluateInteger(value, schema, cursor);
      case ApiVocabulary.NUMBER -> evaluateNumber(value, schema, cursor);
      case ApiVocabulary.BOOLEAN ->
          value instanceof Boolean
              ? null
              : failure(ApiVocabulary.INVALID_TYPE, cursor, " must be a boolean");
      default -> throw new IllegalStateException("unsupported schema type: " + type);
    };
  }

  @SuppressWarnings(ApiVocabulary.UNCHECKED)
  private static ValidationFailure evaluateObject(
      Object value,
      Map<String, Object> schema,
      PointerCursor cursor,
      Map<String, Map<String, Object>> definitions) {
    if (!(value instanceof Map<?, ?> object)) {
      return failure(ApiVocabulary.INVALID_TYPE, cursor, " must be an object");
    }
    int minimumProperties =
        ((Number) schema.getOrDefault(ApiVocabulary.MIN_PROPERTIES, 0)).intValue();
    int maximumProperties =
        ((Number) schema.getOrDefault(ApiVocabulary.MAX_PROPERTIES, MAX_INT)).intValue();
    if (object.size() < minimumProperties || object.size() > maximumProperties) {
      return rangeFailure(
          "invalid_count",
          cursor,
          " must contain ",
          minimumProperties,
          maximumProperties,
          " fields");
    }
    for (Object required : (List<?>) schema.getOrDefault(ApiVocabulary.REQUIRED, List.of())) {
      if (!object.containsKey(required)) {
        return fieldFailure(ApiVocabulary.MISSING_FIELD, cursor, required, " is required");
      }
    }
    Map<String, Object> properties =
        (Map<String, Object>) schema.getOrDefault(ApiVocabulary.PROPERTIES, Map.of());
    boolean additional = !Boolean.FALSE.equals(schema.get(ApiVocabulary.ADDITIONAL_PROPERTIES));
    for (Map.Entry<?, ?> entry : object.entrySet()) {
      if (!(entry.getKey() instanceof String key)) {
        return failure("invalid_field", cursor, " field names must be strings");
      }
      Object propertySchema = properties.get(key);
      if (propertySchema == null) {
        if (!additional) {
          return fieldFailure("unknown_field", cursor, key, " is not allowed");
        }
      } else {
        if (cursor != null) {
          cursor.pushKey(key);
        }
        try {
          ValidationFailure failure =
              evaluate(entry.getValue(), (Map<String, Object>) propertySchema, cursor, definitions);
          if (failure != null) {
            return failure;
          }
        } finally {
          if (cursor != null) {
            cursor.pop();
          }
        }
      }
    }
    return null;
  }

  @SuppressWarnings(ApiVocabulary.UNCHECKED)
  private static ValidationFailure evaluateArray(
      Object value,
      Map<String, Object> schema,
      PointerCursor cursor,
      Map<String, Map<String, Object>> definitions) {
    if (!(value instanceof List<?> items)) {
      return failure(ApiVocabulary.INVALID_TYPE, cursor, " must be an array");
    }
    int minimum = ((Number) schema.getOrDefault(ApiVocabulary.MIN_ITEMS, 0)).intValue();
    int maximum = ((Number) schema.getOrDefault(ApiVocabulary.MAX_ITEMS, MAX_INT)).intValue();
    if (items.size() < minimum || items.size() > maximum) {
      return rangeFailure("invalid_count", cursor, " must contain ", minimum, maximum, " items");
    }
    Map<String, Object> itemSchema =
        (Map<String, Object>) schema.getOrDefault(ApiVocabulary.ITEMS, Map.of());
    for (int index = 0; index < items.size(); index++) {
      if (cursor != null) {
        cursor.pushIndex(index);
      }
      try {
        ValidationFailure failure = evaluate(items.get(index), itemSchema, cursor, definitions);
        if (failure != null) {
          return failure;
        }
      } finally {
        if (cursor != null) {
          cursor.pop();
        }
      }
    }
    return null;
  }

  private static ValidationFailure evaluateString(
      Object value, Map<String, Object> schema, PointerCursor cursor) {
    if (!(value instanceof String text)) {
      return failure(ApiVocabulary.INVALID_TYPE, cursor, " must be a string");
    }
    int minimum = ((Number) schema.getOrDefault(ApiVocabulary.MIN_LENGTH, 0)).intValue();
    if (text.length() < minimum) {
      return failure(ApiVocabulary.INVALID_VALUE, cursor, " must not be empty");
    }
    if (schema.get(ApiVocabulary.ENUM) instanceof List<?> values && !values.contains(text)) {
      return failure("invalid_enum", cursor, " has an unsupported value");
    }
    return null;
  }

  private static ValidationFailure evaluateInteger(
      Object value, Map<String, Object> schema, PointerCursor cursor) {
    if (!(value instanceof Byte
        || value instanceof Short
        || value instanceof Integer
        || value instanceof Long)) {
      return failure(ApiVocabulary.INVALID_TYPE, cursor, " must be an integer");
    }
    long number = ((Number) value).longValue();
    long minimum = ((Number) schema.getOrDefault(ApiVocabulary.MINIMUM, MIN_LONG)).longValue();
    long maximum = ((Number) schema.getOrDefault(ApiVocabulary.MAXIMUM, MAX_LONG)).longValue();
    if (number < minimum || number > maximum) {
      return rangeFailure(
          ApiVocabulary.INVALID_VALUE, cursor, " must be in ", minimum, maximum, "");
    }
    return null;
  }

  private static ValidationFailure evaluateNumber(
      Object value, Map<String, Object> schema, PointerCursor cursor) {
    if (!(value instanceof Number number)) {
      return failure(ApiVocabulary.INVALID_TYPE, cursor, " must be a number");
    }
    double actual = number.doubleValue();
    if (!Double.isFinite(actual)) {
      return failure(ApiVocabulary.INVALID_VALUE, cursor, " must be finite");
    }
    double minimum =
        ((Number) schema.getOrDefault(ApiVocabulary.MINIMUM, MIN_DOUBLE)).doubleValue();
    double maximum =
        ((Number) schema.getOrDefault(ApiVocabulary.MAXIMUM, MAX_DOUBLE)).doubleValue();
    if (actual < minimum || actual > maximum) {
      return numberRangeFailure(cursor, minimum, maximum);
    }
    return null;
  }

  private static Map<String, Object> resolveReference(
      String reference, Map<String, Map<String, Object>> definitions) {
    Map<String, Object> resolved = definitions.get(reference.substring("#/$defs/".length()));
    if (resolved == null) {
      throw new IllegalStateException("unresolved schema reference: " + reference);
    }
    return resolved;
  }

  @SuppressWarnings(ApiVocabulary.UNCHECKED)
  private static Map<String, Map<String, Object>> schemaDefinitions(Map<String, Object> schema) {
    Object definitions = schema.get(ApiVocabulary.DEFINITIONS);
    return definitions instanceof Map<?, ?> map
        ? (Map<String, Map<String, Object>>) map
        : DEFAULT_DEFINITIONS;
  }

  private static String escapePointer(String value) {
    return value.replace("~", "~0").replace("/", "~1");
  }

  private static ValidationFailure failure(String code, PointerCursor cursor, String suffix) {
    if (cursor == null) {
      return ValidationFailure.PROBE_FAILURE;
    }
    String target = cursor.format();
    return new ValidationFailure(code, target + suffix, target);
  }

  private static ValidationFailure fieldFailure(
      String code, PointerCursor cursor, Object field, String suffix) {
    if (cursor == null) {
      return ValidationFailure.PROBE_FAILURE;
    }
    String fieldTarget = cursor.format() + "/" + field;
    return new ValidationFailure(code, fieldTarget + suffix, fieldTarget);
  }

  private static ValidationFailure rangeFailure(
      String code, PointerCursor cursor, String prefix, long minimum, long maximum, String suffix) {
    if (cursor == null) {
      return ValidationFailure.PROBE_FAILURE;
    }
    String target = cursor.format();
    return new ValidationFailure(code, target + prefix + minimum + ".." + maximum + suffix, target);
  }

  private static ValidationFailure numberRangeFailure(
      PointerCursor cursor, double minimum, double maximum) {
    if (cursor == null) {
      return ValidationFailure.PROBE_FAILURE;
    }
    String target = cursor.format();
    return new ValidationFailure(
        ApiVocabulary.INVALID_VALUE, target + " must be in " + minimum + ".." + maximum, target);
  }

  private record ValidationFailure(String code, String message, String target) {
    private static final ValidationFailure PROBE_FAILURE = new ValidationFailure("", "", "");
  }

  private static final class PointerCursor {
    private final String root;
    private final List<Object> segments = new ArrayList<>();

    PointerCursor(String root) {
      this.root = root;
    }

    void pushKey(String key) {
      segments.add(key);
    }

    void pushIndex(int index) {
      segments.add(index);
    }

    void pop() {
      segments.removeLast();
    }

    String format() {
      if (segments.isEmpty()) {
        return root;
      }
      StringBuilder builder = new StringBuilder(String.valueOf(root));
      for (Object segment : segments) {
        builder.append('/');
        if (segment instanceof String key) {
          builder.append(escapePointer(key));
        } else {
          builder.append(segment);
        }
      }
      return builder.toString();
    }
  }
}
