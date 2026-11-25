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

  public static Map<String, Object> taggedOneOf(
      String propertyName, List<Map<String, Object>> schemas) {
    if (propertyName == null || propertyName.isBlank()) {
      throw new IllegalArgumentException("discriminator propertyName must not be blank");
    }
    if (schemas == null || schemas.isEmpty()) {
      throw new IllegalArgumentException("taggedOneOf requires at least one branch schema");
    }
    List<Map<String, Object>> copied = List.copyOf(schemas);
    java.util.Set<String> seenTags = new java.util.LinkedHashSet<>();
    for (Map<String, Object> branch : copied) {
      String tag = branchTag(branch, propertyName);
      if (tag == null || tag.isBlank()) {
        throw new IllegalArgumentException(
            "taggedOneOf branch is missing single-value string tag for " + propertyName);
      }
      if (!seenTags.add(tag)) {
        throw new IllegalArgumentException(
            "duplicate taggedOneOf discriminator value for " + propertyName + ": " + tag);
      }
    }
    Map<String, Object> union = new LinkedHashMap<>();
    union.put(ApiVocabulary.ONE_OF, copied);
    union.put(ApiVocabulary.DISCRIMINATOR, Map.of("propertyName", propertyName));
    return java.util.Collections.unmodifiableMap(union);
  }

  @SafeVarargs
  public static Map<String, Object> taggedOneOf(
      String propertyName, Map<String, Object>... schemas) {
    return taggedOneOf(propertyName, List.of(schemas));
  }

  public static Map<String, Object> withDefault(Map<String, Object> schema, Object defaultValue) {
    Map<String, Object> copy = new LinkedHashMap<>(schema);
    copy.put(ApiVocabulary.DEFAULT, defaultValue);
    return java.util.Collections.unmodifiableMap(copy);
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
    return taggedOneOf(ApiVocabulary.KIND, named, pointer, array, untyped);
  }

  private static final Integer MAX_INT = Integer.MAX_VALUE;
  private static final Long MIN_LONG = Long.MIN_VALUE;
  private static final Long MAX_LONG = Long.MAX_VALUE;
  private static final Double MIN_DOUBLE = -Double.MAX_VALUE;
  private static final Double MAX_DOUBLE = Double.MAX_VALUE;

  public static void validate(Object value, Map<String, Object> schema, String target) {
    Map<String, Map<String, Object>> definitions = schemaDefinitions(schema);
    if (matches(value, schema, definitions)) {
      return;
    }
    PointerCursor cursor = new PointerCursor(target);
    ValidationFailure failure = findFailure(value, schema, cursor, definitions);
    if (failure == null) {
      throw new IllegalStateException("schema mismatch without failure diagnostic");
    }
    throw ApiException.badRequest(failure.code(), failure.message(), failure.target());
  }

  @SuppressWarnings(ApiVocabulary.UNCHECKED)
  private static boolean matches(
      Object value,
      Map<String, Object> schema,
      Map<String, Map<String, Object>> definitions) {
    Object ref = schema.get(ApiVocabulary.REFERENCE);
    if (ref instanceof String reference && reference.startsWith("#/$defs/")) {
      return matches(value, resolveReference(reference, definitions), definitions);
    }
    Object type = schema.get(ApiVocabulary.TYPE);
    if (type != null && !matchesType(value, String.valueOf(type), schema, definitions)) {
      return false;
    }
    if (schema.get(ApiVocabulary.ONE_OF) instanceof List<?> alternatives) {
      String discriminator = discriminatorProperty(schema);
      if (discriminator != null) {
        if (!(value instanceof Map<?, ?> object)
            || !(object.get(discriminator) instanceof String tag)) {
          return false;
        }
        Map<String, Object> matched = findTaggedBranch(alternatives, discriminator, tag);
        return matched != null && matches(value, matched, definitions);
      }
      int matchCount = 0;
      for (Object rawAlternative : alternatives) {
        if (matches(value, (Map<String, Object>) rawAlternative, definitions)) {
          matchCount++;
        }
      }
      return matchCount == EXACT_UNION_MATCHES;
    }
    return true;
  }

  private static boolean matchesType(
      Object value,
      String type,
      Map<String, Object> schema,
      Map<String, Map<String, Object>> definitions) {
    return switch (type) {
      case ApiVocabulary.NULL -> value == null;
      case ApiVocabulary.OBJECT -> matchesObject(value, schema, definitions);
      case ApiVocabulary.ARRAY -> matchesArray(value, schema, definitions);
      case ApiVocabulary.STRING -> matchesString(value, schema);
      case ApiVocabulary.INTEGER -> matchesInteger(value, schema);
      case ApiVocabulary.NUMBER -> matchesNumber(value, schema);
      case ApiVocabulary.BOOLEAN -> value instanceof Boolean;
      default -> throw new IllegalStateException("unsupported schema type: " + type);
    };
  }

  @SuppressWarnings(ApiVocabulary.UNCHECKED)
  private static boolean matchesObject(
      Object value,
      Map<String, Object> schema,
      Map<String, Map<String, Object>> definitions) {
    if (!(value instanceof Map<?, ?> object)) {
      return false;
    }
    int minimumProperties =
        ((Number) schema.getOrDefault(ApiVocabulary.MIN_PROPERTIES, 0)).intValue();
    int maximumProperties =
        ((Number) schema.getOrDefault(ApiVocabulary.MAX_PROPERTIES, MAX_INT)).intValue();
    if (object.size() < minimumProperties || object.size() > maximumProperties) {
      return false;
    }
    for (Object required : (List<?>) schema.getOrDefault(ApiVocabulary.REQUIRED, List.of())) {
      if (!object.containsKey(required)) {
        return false;
      }
    }
    Map<String, Object> properties =
        (Map<String, Object>) schema.getOrDefault(ApiVocabulary.PROPERTIES, Map.of());
    boolean additional = !Boolean.FALSE.equals(schema.get(ApiVocabulary.ADDITIONAL_PROPERTIES));
    for (Map.Entry<?, ?> entry : object.entrySet()) {
      if (!(entry.getKey() instanceof String key)) {
        return false;
      }
      Object propertySchema = properties.get(key);
      if (propertySchema == null) {
        if (!additional) {
          return false;
        }
      } else if (!matches(entry.getValue(), (Map<String, Object>) propertySchema, definitions)) {
        return false;
      }
    }
    return true;
  }

  @SuppressWarnings(ApiVocabulary.UNCHECKED)
  private static boolean matchesArray(
      Object value,
      Map<String, Object> schema,
      Map<String, Map<String, Object>> definitions) {
    if (!(value instanceof List<?> items)) {
      return false;
    }
    int minimum = ((Number) schema.getOrDefault(ApiVocabulary.MIN_ITEMS, 0)).intValue();
    int maximum = ((Number) schema.getOrDefault(ApiVocabulary.MAX_ITEMS, MAX_INT)).intValue();
    if (items.size() < minimum || items.size() > maximum) {
      return false;
    }
    Map<String, Object> itemSchema =
        (Map<String, Object>) schema.getOrDefault(ApiVocabulary.ITEMS, Map.of());
    for (int index = 0; index < items.size(); index++) {
      if (!matches(items.get(index), itemSchema, definitions)) {
        return false;
      }
    }
    return true;
  }

  private static boolean matchesString(Object value, Map<String, Object> schema) {
    if (!(value instanceof String text)) {
      return false;
    }
    int minimum = ((Number) schema.getOrDefault(ApiVocabulary.MIN_LENGTH, 0)).intValue();
    if (text.length() < minimum) {
      return false;
    }
    if (schema.get(ApiVocabulary.CONST) instanceof String expected && !expected.equals(text)) {
      return false;
    }
    return !(schema.get(ApiVocabulary.ENUM) instanceof List<?> values) || values.contains(text);
  }

  private static boolean matchesInteger(Object value, Map<String, Object> schema) {
    if (!(value instanceof Byte
        || value instanceof Short
        || value instanceof Integer
        || value instanceof Long)) {
      return false;
    }
    long number = ((Number) value).longValue();
    long minimum = ((Number) schema.getOrDefault(ApiVocabulary.MINIMUM, MIN_LONG)).longValue();
    long maximum = ((Number) schema.getOrDefault(ApiVocabulary.MAXIMUM, MAX_LONG)).longValue();
    return !(number < minimum || number > maximum);
  }

  private static boolean matchesNumber(Object value, Map<String, Object> schema) {
    if (!(value instanceof Number number)) {
      return false;
    }
    double actual = number.doubleValue();
    if (!Double.isFinite(actual)) {
      return false;
    }
    double minimum =
        ((Number) schema.getOrDefault(ApiVocabulary.MINIMUM, MIN_DOUBLE)).doubleValue();
    double maximum =
        ((Number) schema.getOrDefault(ApiVocabulary.MAXIMUM, MAX_DOUBLE)).doubleValue();
    return !(actual < minimum || actual > maximum);
  }

  @SuppressWarnings(ApiVocabulary.UNCHECKED)
  private static ValidationFailure findFailure(
      Object value,
      Map<String, Object> schema,
      PointerCursor cursor,
      Map<String, Map<String, Object>> definitions) {
    Object ref = schema.get(ApiVocabulary.REFERENCE);
    if (ref instanceof String reference && reference.startsWith("#/$defs/")) {
      return findFailure(value, resolveReference(reference, definitions), cursor, definitions);
    }
    Object type = schema.get(ApiVocabulary.TYPE);
    if (type != null) {
      ValidationFailure typeFailure =
          findTypeFailure(value, String.valueOf(type), schema, cursor, definitions);
      if (typeFailure != null) {
        return typeFailure;
      }
    }
    if (schema.get(ApiVocabulary.ONE_OF) instanceof List<?> alternatives) {
      String discriminator = discriminatorProperty(schema);
      if (discriminator != null) {
        return findDiscriminatedFailure(value, alternatives, discriminator, cursor, definitions);
      }
      ValidationFailure firstFailure = null;
      int matchCount = 0;
      for (Object rawAlternative : alternatives) {
        Map<String, Object> alternative = (Map<String, Object>) rawAlternative;
        if (firstFailure == null) {
          ValidationFailure failure = findFailure(value, alternative, cursor, definitions);
          if (failure == null) {
            matchCount++;
          } else {
            firstFailure = failure;
          }
        } else if (matches(value, alternative, definitions)) {
          matchCount++;
        }
      }
      if (matchCount != EXACT_UNION_MATCHES) {
        if (firstFailure != null) {
          return new ValidationFailure(
              "invalid_union", firstFailure.message(), firstFailure.target());
        }
        String target = cursor.format();
        return new ValidationFailure(
            "invalid_union", target + " must match exactly one schema", target);
      }
      return null;
    }
    return null;
  }

  private static ValidationFailure findTypeFailure(
      Object value,
      String type,
      Map<String, Object> schema,
      PointerCursor cursor,
      Map<String, Map<String, Object>> definitions) {
    return switch (type) {
      case ApiVocabulary.NULL ->
          value == null ? null : failure(ApiVocabulary.INVALID_TYPE, cursor, " must be null");
      case ApiVocabulary.OBJECT -> findObjectFailure(value, schema, cursor, definitions);
      case ApiVocabulary.ARRAY -> findArrayFailure(value, schema, cursor, definitions);
      case ApiVocabulary.STRING -> findStringFailure(value, schema, cursor);
      case ApiVocabulary.INTEGER -> findIntegerFailure(value, schema, cursor);
      case ApiVocabulary.NUMBER -> findNumberFailure(value, schema, cursor);
      case ApiVocabulary.BOOLEAN ->
          value instanceof Boolean
              ? null
              : failure(ApiVocabulary.INVALID_TYPE, cursor, " must be a boolean");
      default -> throw new IllegalStateException("unsupported schema type: " + type);
    };
  }

  private static ValidationFailure findDiscriminatedFailure(
      Object value,
      List<?> alternatives,
      String propertyName,
      PointerCursor cursor,
      Map<String, Map<String, Object>> definitions) {
    if (!(value instanceof Map<?, ?> object)) {
      return failure(ApiVocabulary.INVALID_TYPE, cursor, " must be an object");
    }
    for (Map.Entry<?, ?> entry : object.entrySet()) {
      if (!(entry.getKey() instanceof String)) {
        return failure("invalid_field", cursor, " field names must be strings");
      }
    }
    if (!object.containsKey(propertyName)) {
      String fieldTarget = cursor.format() + "/" + propertyName;
      return new ValidationFailure(
          ApiVocabulary.MISSING_FIELD, fieldTarget + " is required", fieldTarget);
    }
    Object rawTag = object.get(propertyName);
    Map<String, Object> matchedBranch;
    cursor.pushKey(propertyName);
    try {
      if (!(rawTag instanceof String tag)) {
        return failure(ApiVocabulary.INVALID_TYPE, cursor, " must be a string");
      }
      matchedBranch = findTaggedBranch(alternatives, propertyName, tag);
      if (matchedBranch == null) {
        return failure(
            "invalid_enum",
            cursor,
            " must be one of: " + String.join(", ", allowedTags(alternatives, propertyName)));
      }
    } finally {
      cursor.pop();
    }
    return findFailure(value, matchedBranch, cursor, definitions);
  }

  @SuppressWarnings(ApiVocabulary.UNCHECKED)
  private static ValidationFailure findObjectFailure(
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
      return failure(
          "invalid_count",
          cursor,
          " must contain " + minimumProperties + ".." + maximumProperties + " fields");
    }
    for (Object required : (List<?>) schema.getOrDefault(ApiVocabulary.REQUIRED, List.of())) {
      if (!object.containsKey(required)) {
        String fieldTarget = cursor.format() + "/" + required;
        return new ValidationFailure("missing_field", fieldTarget + " is required", fieldTarget);
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
          String fieldTarget = cursor.format() + "/" + key;
          return new ValidationFailure(
              "unknown_field", fieldTarget + " is not allowed", fieldTarget);
        }
      } else {
        cursor.pushKey(key);
        try {
          ValidationFailure failure =
              findFailure(entry.getValue(), (Map<String, Object>) propertySchema, cursor, definitions);
          if (failure != null) {
            return failure;
          }
        } finally {
          cursor.pop();
        }
      }
    }
    return null;
  }

  @SuppressWarnings(ApiVocabulary.UNCHECKED)
  private static ValidationFailure findArrayFailure(
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
      return failure(
          "invalid_count", cursor, " must contain " + minimum + ".." + maximum + " items");
    }
    Map<String, Object> itemSchema =
        (Map<String, Object>) schema.getOrDefault(ApiVocabulary.ITEMS, Map.of());
    for (int index = 0; index < items.size(); index++) {
      cursor.pushIndex(index);
      try {
        ValidationFailure failure = findFailure(items.get(index), itemSchema, cursor, definitions);
        if (failure != null) {
          return failure;
        }
      } finally {
        cursor.pop();
      }
    }
    return null;
  }

  private static ValidationFailure findStringFailure(
      Object value, Map<String, Object> schema, PointerCursor cursor) {
    if (!(value instanceof String text)) {
      return failure(ApiVocabulary.INVALID_TYPE, cursor, " must be a string");
    }
    int minimum = ((Number) schema.getOrDefault(ApiVocabulary.MIN_LENGTH, 0)).intValue();
    if (text.length() < minimum) {
      return failure(ApiVocabulary.INVALID_VALUE, cursor, " must not be empty");
    }
    if (schema.get(ApiVocabulary.CONST) instanceof String expected && !expected.equals(text)) {
      return failure("invalid_enum", cursor, " must equal " + expected);
    }
    if (schema.get(ApiVocabulary.ENUM) instanceof List<?> values && !values.contains(text)) {
      String allowed =
          values.stream().map(String::valueOf).collect(java.util.stream.Collectors.joining(", "));
      return failure("invalid_enum", cursor, " must be one of: " + allowed);
    }
    return null;
  }

  @SuppressWarnings(ApiVocabulary.UNCHECKED)
  private static String branchTag(Map<String, Object> branch, String propertyName) {
    if (!ApiVocabulary.OBJECT.equals(branch.get(ApiVocabulary.TYPE))) {
      return null;
    }
    if (!(branch.get(ApiVocabulary.PROPERTIES) instanceof Map<?, ?> properties)) {
      return null;
    }
    if (!(properties.get(propertyName) instanceof Map<?, ?> tagSchema)) {
      return null;
    }
    if (tagSchema.get(ApiVocabulary.CONST) instanceof String constant && !constant.isBlank()) {
      return constant;
    }
    if (tagSchema.get(ApiVocabulary.ENUM) instanceof List<?> values
        && values.size() == 1
        && values.getFirst() instanceof String single
        && !single.isBlank()) {
      return single;
    }
    return null;
  }

  private static String discriminatorProperty(Map<String, Object> schema) {
    if (schema.get(ApiVocabulary.DISCRIMINATOR) instanceof Map<?, ?> discriminator
        && discriminator.get("propertyName") instanceof String propertyName
        && !propertyName.isBlank()) {
      return propertyName;
    }
    return null;
  }

  @SuppressWarnings(ApiVocabulary.UNCHECKED)
  private static Map<String, Object> findTaggedBranch(
      List<?> alternatives, String propertyName, String tag) {
    for (Object rawAlternative : alternatives) {
      Map<String, Object> branch = (Map<String, Object>) rawAlternative;
      if (tag.equals(branchTag(branch, propertyName))) {
        return branch;
      }
    }
    return null;
  }

  @SuppressWarnings(ApiVocabulary.UNCHECKED)
  private static List<String> allowedTags(List<?> alternatives, String propertyName) {
    List<String> tags = new ArrayList<>(alternatives.size());
    for (Object rawAlternative : alternatives) {
      String tag = branchTag((Map<String, Object>) rawAlternative, propertyName);
      if (tag != null) {
        tags.add(tag);
      }
    }
    return tags;
  }

  static Map<String, Map<String, Object>> definitionsOf(Map<String, Object> schema) {
    return schemaDefinitions(schema);
  }

  static Map<String, Object> dereference(
      Map<String, Object> schema, Map<String, Map<String, Object>> definitions) {
    Object ref = schema.get(ApiVocabulary.REFERENCE);
    if (ref instanceof String reference && reference.startsWith("#/$defs/")) {
      return dereference(resolveReference(reference, definitions), definitions);
    }
    return schema;
  }

  static Map<String, Object> selectTaggedBranch(
      Map<String, Object> schema, Map<String, Object> object) {
    String discriminator = discriminatorProperty(schema);
    if (discriminator == null
        || !(schema.get(ApiVocabulary.ONE_OF) instanceof List<?> alternatives)
        || !(object.get(discriminator) instanceof String tag)) {
      return null;
    }
    return findTaggedBranch(alternatives, discriminator, tag);
  }

  @SuppressWarnings(ApiVocabulary.UNCHECKED)
  static String rebasePointer(String pointer, Map<String, Object> requestSchema) {
    if (pointer == null || pointer.isBlank() || requestSchema == null) {
      return pointer;
    }
    String normalized = pointer.startsWith("/") ? pointer : "/" + pointer;
    int nextSlash = normalized.indexOf('/', 1);
    String firstSegment =
        unescapePointer(
            nextSlash < 0 ? normalized.substring(1) : normalized.substring(1, nextSlash));
    if (firstSegment.isEmpty()) {
      return normalized;
    }
    Map<String, Map<String, Object>> definitions = schemaDefinitions(requestSchema);
    Map<String, Object> topProperties = collectObjectProperties(requestSchema, definitions);
    if (topProperties.containsKey(firstSegment)) {
      return normalized;
    }
    String matchedContainer = null;
    for (Map.Entry<String, Object> entry : topProperties.entrySet()) {
      if (!(entry.getValue() instanceof Map<?, ?> childRaw)) {
        continue;
      }
      Map<String, Object> childProperties =
          collectObjectProperties((Map<String, Object>) childRaw, definitions);
      if (childProperties.containsKey(firstSegment)) {
        if (matchedContainer != null && !matchedContainer.equals(entry.getKey())) {
          return normalized;
        }
        matchedContainer = entry.getKey();
      }
    }
    return matchedContainer == null
        ? normalized
        : "/" + escapePointer(matchedContainer) + normalized;
  }

  @SuppressWarnings(ApiVocabulary.UNCHECKED)
  private static Map<String, Object> collectObjectProperties(
      Map<String, Object> rawSchema, Map<String, Map<String, Object>> definitions) {
    Map<String, Object> schema = dereference(rawSchema, definitions);
    Map<String, Object> collected = new LinkedHashMap<>();
    if (schema.get(ApiVocabulary.PROPERTIES) instanceof Map<?, ?> properties) {
      for (Map.Entry<?, ?> entry : properties.entrySet()) {
        collected.put(String.valueOf(entry.getKey()), entry.getValue());
      }
    }
    if (schema.get(ApiVocabulary.ONE_OF) instanceof List<?> alternatives) {
      for (Object rawAlternative : alternatives) {
        if (rawAlternative instanceof Map<?, ?> branch) {
          collectObjectProperties((Map<String, Object>) branch, definitions)
              .forEach(collected::putIfAbsent);
        }
      }
    }
    return collected;
  }

  private static String unescapePointer(String value) {
    return value.replace("~1", "/").replace("~0", "~");
  }

  private static ValidationFailure findIntegerFailure(
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
      return failure(
          ApiVocabulary.INVALID_VALUE, cursor, " must be in " + minimum + ".." + maximum);
    }
    return null;
  }

  private static ValidationFailure findNumberFailure(
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
      return failure(
          ApiVocabulary.INVALID_VALUE, cursor, " must be in " + minimum + ".." + maximum);
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
    String target = cursor.format();
    return new ValidationFailure(code, target + suffix, target);
  }

  private record ValidationFailure(String code, String message, String target) {}

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
