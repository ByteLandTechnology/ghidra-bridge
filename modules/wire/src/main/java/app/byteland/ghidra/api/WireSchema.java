package app.byteland.ghidra.api;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Builds JSON Schema maps and validates decoded JSON values against them.
 */
public final class WireSchema {
  private static final int EXACT_UNION_MATCHES = 1;

  private WireSchema() {}

  /**
   * Returns an unconstrained JSON Schema that accepts any value.
   *
   * @return empty schema map
   */
  public static Map<String, Object> any() {
    return Map.of();
  }

  /**
   * Returns a JSON Schema for any string value.
   *
   * @return string schema map
   */
  public static Map<String, Object> string() {
    return Map.of(ApiVocabulary.TYPE, ApiVocabulary.STRING);
  }

  /**
   * Returns a JSON Schema for strings with at least one character.
   *
   * @return non-empty string schema map
   */
  public static Map<String, Object> nonBlankString() {
    return Map.of(ApiVocabulary.TYPE, ApiVocabulary.STRING, ApiVocabulary.MIN_LENGTH, 1);
  }

  /**
   * Returns a JSON Schema for a string restricted to the given sorted enum values.
   *
   * @param values permitted string literals
   * @return string enum schema map
   */
  public static Map<String, Object> stringEnum(String... values) {
    List<String> sorted = java.util.Arrays.stream(values).sorted().toList();
    return Map.of(ApiVocabulary.TYPE, ApiVocabulary.STRING, ApiVocabulary.ENUM, sorted);
  }

  /**
   * Returns a JSON Schema for boolean values.
   *
   * @return boolean schema map
   */
  public static Map<String, Object> bool() {
    return Map.of(ApiVocabulary.TYPE, ApiVocabulary.BOOLEAN);
  }

  /**
   * Returns a JSON Schema for bounded integer values.
   *
   * @param minimum inclusive lower bound
   * @param maximum inclusive upper bound
   * @return bounded integer schema map
   */
  public static Map<String, Object> integer(long minimum, long maximum) {
    return Map.of(
        ApiVocabulary.TYPE,
        ApiVocabulary.INTEGER,
        ApiVocabulary.MINIMUM,
        minimum,
        ApiVocabulary.MAXIMUM,
        maximum);
  }

  /**
   * Returns a JSON Schema for bounded finite floating-point numbers.
   *
   * @param minimum inclusive lower bound
   * @param maximum inclusive upper bound
   * @return bounded number schema map
   */
  public static Map<String, Object> number(double minimum, double maximum) {
    return Map.of(
        ApiVocabulary.TYPE,
        ApiVocabulary.NUMBER,
        ApiVocabulary.MINIMUM,
        minimum,
        ApiVocabulary.MAXIMUM,
        maximum);
  }

  /**
   * Returns a JSON Schema for bounded arrays whose elements match {@code items}.
   *
   * @param items element schema map
   * @param minimum minimum element count
   * @param maximum maximum element count
   * @return array schema map
   */
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

  /**
   * Returns a closed JSON Schema object with fixed properties and required field names.
   *
   * @param properties map of property names to property schemas
   * @param required required property names
   * @return closed object schema map
   */
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

  /**
   * Returns an open JSON Schema object that permits arbitrary properties.
   *
   * @return open object schema map
   */
  public static Map<String, Object> openObject() {
    return Map.of(
        ApiVocabulary.TYPE, ApiVocabulary.OBJECT, ApiVocabulary.ADDITIONAL_PROPERTIES, true);
  }

  /**
   * Returns the JSON Schema for serialized {@link BridgeError} objects.
   *
   * @return bridge error schema map
   */
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

  /**
   * Wraps a JSON Schema so that either {@code schema} or {@code null} is accepted.
   *
   * @param schema non-null value schema
   * @return nullable union schema map
   */
  public static Map<String, Object> nullable(Map<String, Object> schema) {
    return Map.of(
        ApiVocabulary.ONE_OF, List.of(schema, Map.of(ApiVocabulary.TYPE, ApiVocabulary.NULL)));
  }

  /**
   * Returns a {@code oneOf} union schema over a list of alternative schemas.
   *
   * @param schemas alternative schema maps
   * @return union schema map
   */
  public static Map<String, Object> oneOf(List<Map<String, Object>> schemas) {
    return Map.of(ApiVocabulary.ONE_OF, List.copyOf(schemas));
  }

  /**
   * Returns a {@code oneOf} union schema with two alternatives.
   *
   * @param first first alternative schema
   * @param second second alternative schema
   * @return union schema map
   */
  public static Map<String, Object> oneOf(Map<String, Object> first, Map<String, Object> second) {
    return oneOf(List.of(first, second));
  }

  /**
   * Returns a {@code oneOf} union schema with three alternatives.
   *
   * @param first first alternative schema
   * @param second second alternative schema
   * @param third third alternative schema
   * @return union schema map
   */
  public static Map<String, Object> oneOf(
      Map<String, Object> first, Map<String, Object> second, Map<String, Object> third) {
    return oneOf(List.of(first, second, third));
  }

  /**
   * Returns a {@code oneOf} union schema with four alternatives.
   *
   * @param first first alternative schema
   * @param second second alternative schema
   * @param third third alternative schema
   * @param fourth fourth alternative schema
   * @return union schema map
   */
  public static Map<String, Object> oneOf(
      Map<String, Object> first,
      Map<String, Object> second,
      Map<String, Object> third,
      Map<String, Object> fourth) {
    return oneOf(List.of(first, second, third, fourth));
  }

  /**
   * Returns a {@code oneOf} union schema with five alternatives.
   *
   * @param first first alternative schema
   * @param second second alternative schema
   * @param third third alternative schema
   * @param fourth fourth alternative schema
   * @param fifth fifth alternative schema
   * @return union schema map
   */
  public static Map<String, Object> oneOf(
      Map<String, Object> first,
      Map<String, Object> second,
      Map<String, Object> third,
      Map<String, Object> fourth,
      Map<String, Object> fifth) {
    return oneOf(List.of(first, second, third, fourth, fifth));
  }

  /**
   * Returns a schema {@code $ref} pointer to the shared {@code data_type_reference} definition.
   *
   * @return schema reference map
   */
  public static Map<String, Object> dataTypeReference() {
    return Map.of(ApiVocabulary.REFERENCE, "#/$defs/data_type_reference");
  }

  /**
   * Attaches the shared {@code $defs} dictionary to a root schema map.
   *
   * @param schema root schema map
   * @return copy of {@code schema} with shared definitions attached
   */
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

  /**
   * Validates a decoded JSON value against a JSON Schema and throws {@link ApiException} on
   * mismatch.
   *
   * @param value decoded JSON value
   * @param schema JSON Schema map
   * @param target JSON pointer prefix for validation errors
   */
  public static void validate(Object value, Map<String, Object> schema, String target) {
    validate(value, schema, target, schemaDefinitions(schema));
  }

  @SuppressWarnings(ApiVocabulary.UNCHECKED)
  private static void validate(
      Object value,
      Map<String, Object> schema,
      String target,
      Map<String, Map<String, Object>> definitions) {
    Object ref = schema.get(ApiVocabulary.REFERENCE);
    if (ref instanceof String reference && reference.startsWith("#/$defs/")) {
      Map<String, Object> resolved = definitions.get(reference.substring("#/$defs/".length()));
      if (resolved == null) {
        throw new IllegalStateException("unresolved schema reference: " + reference);
      }
      validate(value, resolved, target, definitions);
      return;
    }
    if (schema.get(ApiVocabulary.ONE_OF) instanceof List<?> alternatives) {
      List<ApiException> failures = new ArrayList<>();
      int matches = 0;
      for (Object rawAlternative : alternatives) {
        try {
          validate(value, (Map<String, Object>) rawAlternative, target, definitions);
          matches++;
        } catch (ApiException failure) {
          failures.add(failure);
        }
      }
      if (matches != EXACT_UNION_MATCHES) {
        ApiException failure = failures.isEmpty() ? null : failures.getFirst();
        throw ApiException.badRequest(
            "invalid_union",
            failure == null ? target + " must match exactly one schema" : failure.getMessage(),
            failure == null ? target : failure.error().target());
      }
      return;
    }
    Object type = schema.get(ApiVocabulary.TYPE);
    if (type == null) {
      return;
    }
    switch (String.valueOf(type)) {
      case ApiVocabulary.NULL -> {
        if (value != null) fail(ApiVocabulary.INVALID_TYPE, target + " must be null", target);
      }
      case ApiVocabulary.OBJECT -> validateObject(value, schema, target, definitions);
      case ApiVocabulary.ARRAY -> validateArray(value, schema, target, definitions);
      case ApiVocabulary.STRING -> validateString(value, schema, target);
      case ApiVocabulary.INTEGER -> validateInteger(value, schema, target);
      case ApiVocabulary.NUMBER -> validateNumber(value, schema, target);
      case ApiVocabulary.BOOLEAN -> {
        if (!(value instanceof Boolean))
          fail(ApiVocabulary.INVALID_TYPE, target + " must be a boolean", target);
      }
      default -> throw new IllegalStateException("unsupported schema type: " + type);
    }
  }

  @SuppressWarnings(ApiVocabulary.UNCHECKED)
  private static void validateObject(
      Object value,
      Map<String, Object> schema,
      String target,
      Map<String, Map<String, Object>> definitions) {
    if (!(value instanceof Map<?, ?>)) {
      fail(ApiVocabulary.INVALID_TYPE, target + " must be an object", target);
    }
    Map<?, ?> object = (Map<?, ?>) value;
    int minimumProperties =
        ((Number) schema.getOrDefault(ApiVocabulary.MIN_PROPERTIES, 0)).intValue();
    int maximumProperties =
        ((Number) schema.getOrDefault(ApiVocabulary.MAX_PROPERTIES, Integer.MAX_VALUE)).intValue();
    if (object.size() < minimumProperties || object.size() > maximumProperties) {
      fail(
          "invalid_count",
          target + " must contain " + minimumProperties + ".." + maximumProperties + " fields",
          target);
    }
    for (Object required : (List<?>) schema.getOrDefault(ApiVocabulary.REQUIRED, List.of())) {
      if (!object.containsKey(required)) {
        fail("missing_field", target + "/" + required + " is required", target + "/" + required);
      }
    }
    Map<String, Object> properties =
        (Map<String, Object>) schema.getOrDefault(ApiVocabulary.PROPERTIES, Map.of());
    boolean additional = !Boolean.FALSE.equals(schema.get(ApiVocabulary.ADDITIONAL_PROPERTIES));
    for (Map.Entry<?, ?> entry : object.entrySet()) {
      if (!(entry.getKey() instanceof String)) {
        fail("invalid_field", target + " field names must be strings", target);
      }
      String key = (String) entry.getKey();
      Object propertySchema = properties.get(key);
      if (propertySchema == null) {
        if (!additional) {
          fail("unknown_field", target + "/" + key + " is not allowed", target + "/" + key);
        }
      } else {
        validate(
            entry.getValue(),
            (Map<String, Object>) propertySchema,
            target + "/" + escapePointer(key),
            definitions);
      }
    }
  }

  @SuppressWarnings(ApiVocabulary.UNCHECKED)
  private static void validateArray(
      Object value,
      Map<String, Object> schema,
      String target,
      Map<String, Map<String, Object>> definitions) {
    if (!(value instanceof List<?>)) {
      fail(ApiVocabulary.INVALID_TYPE, target + " must be an array", target);
    }
    List<?> items = (List<?>) value;
    int minimum = ((Number) schema.getOrDefault(ApiVocabulary.MIN_ITEMS, 0)).intValue();
    int maximum =
        ((Number) schema.getOrDefault(ApiVocabulary.MAX_ITEMS, Integer.MAX_VALUE)).intValue();
    if (items.size() < minimum || items.size() > maximum) {
      fail(
          "invalid_count", target + " must contain " + minimum + ".." + maximum + " items", target);
    }
    Map<String, Object> itemSchema =
        (Map<String, Object>) schema.getOrDefault(ApiVocabulary.ITEMS, Map.of());
    for (int index = 0; index < items.size(); index++) {
      validate(items.get(index), itemSchema, target + "/" + index, definitions);
    }
  }

  private static void validateString(Object value, Map<String, Object> schema, String target) {
    if (!(value instanceof String)) {
      fail(ApiVocabulary.INVALID_TYPE, target + " must be a string", target);
    }
    String text = (String) value;
    int minimum = ((Number) schema.getOrDefault(ApiVocabulary.MIN_LENGTH, 0)).intValue();
    if (text.length() < minimum) {
      fail(ApiVocabulary.INVALID_VALUE, target + " must not be empty", target);
    }
    if (schema.get(ApiVocabulary.ENUM) instanceof List<?> values && !values.contains(text)) {
      fail("invalid_enum", target + " has an unsupported value", target);
    }
  }

  private static void validateInteger(Object value, Map<String, Object> schema, String target) {
    if (!(value instanceof Byte
        || value instanceof Short
        || value instanceof Integer
        || value instanceof Long)) {
      fail(ApiVocabulary.INVALID_TYPE, target + " must be an integer", target);
    }
    long number = ((Number) value).longValue();
    long minimum =
        ((Number) schema.getOrDefault(ApiVocabulary.MINIMUM, Long.MIN_VALUE)).longValue();
    long maximum =
        ((Number) schema.getOrDefault(ApiVocabulary.MAXIMUM, Long.MAX_VALUE)).longValue();
    if (number < minimum || number > maximum) {
      fail(ApiVocabulary.INVALID_VALUE, target + " must be in " + minimum + ".." + maximum, target);
    }
  }

  private static void validateNumber(Object value, Map<String, Object> schema, String target) {
    if (!(value instanceof Number)) {
      fail(ApiVocabulary.INVALID_TYPE, target + " must be a number", target);
    }
    double actual = ((Number) value).doubleValue();
    if (!Double.isFinite(actual)) {
      fail(ApiVocabulary.INVALID_VALUE, target + " must be finite", target);
    }
    double minimum =
        ((Number) schema.getOrDefault(ApiVocabulary.MINIMUM, -Double.MAX_VALUE)).doubleValue();
    double maximum =
        ((Number) schema.getOrDefault(ApiVocabulary.MAXIMUM, Double.MAX_VALUE)).doubleValue();
    if (actual < minimum || actual > maximum) {
      fail(ApiVocabulary.INVALID_VALUE, target + " must be in " + minimum + ".." + maximum, target);
    }
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

  private static void fail(String reason, String message, String target) {
    throw ApiException.badRequest(reason, message, target);
  }
}
