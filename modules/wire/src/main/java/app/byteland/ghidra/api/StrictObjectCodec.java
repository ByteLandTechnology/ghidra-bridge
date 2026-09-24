package app.byteland.ghidra.api;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

final class StrictObjectCodec implements JsonCodec<Map<String, Object>> {
  private final Map<String, Object> publishedSchema;
  private final Map<String, Object> validationSchema;

  StrictObjectCodec(Map<String, Object> schema) {
    this(schema, schema);
  }

  StrictObjectCodec(Map<String, Object> schema, Map<String, Object> validationSchema) {
    this.publishedSchema = Collections.unmodifiableMap(new LinkedHashMap<>(schema));
    this.validationSchema = Collections.unmodifiableMap(new LinkedHashMap<>(validationSchema));
  }

  @Override
  public Map<String, Object> decode(Object value, String target) {
    Object actual = value == null ? Map.of() : value;
    WireSchema.validate(actual, publishedSchema, target);
    @SuppressWarnings("unchecked")
    Map<String, Object> object = (Map<String, Object>) actual;
    Map<String, Object> normalized = normalize(object);
    WireSchema.validate(normalized, validationSchema, target);
    return Collections.unmodifiableMap(normalized);
  }

  @Override
  public Object encode(Map<String, Object> value) {
    WireSchema.validate(value, publishedSchema, "/result");
    return value;
  }

  @Override
  public Map<String, Object> schema() {
    return publishedSchema;
  }

  static Map<String, Object> canonicalSchema(Map<String, Object> internalSchema) {
    Object rawProperties = internalSchema.get(ApiVocabulary.PROPERTIES);
    if (!(rawProperties instanceof Map<?, ?> properties)) return internalSchema;

    Map<String, Object> publishedProperties = new LinkedHashMap<>();
    Map<String, Object> pageProperties = new LinkedHashMap<>();
    Map<String, Object> scanProperties = new LinkedHashMap<>();
    Map<String, Object> projectionProperties = new LinkedHashMap<>();
    boolean hasScanRange = properties.containsKey("range");
    for (Map.Entry<?, ?> entry : properties.entrySet()) {
      String name = String.valueOf(entry.getKey());
      Object fieldSchema = entry.getValue();
      switch (name) {
        case "limit", "cursor" -> pageProperties.put(name, fieldSchema);
        case "range", "timeout_ms" -> scanProperties.put(name, fieldSchema);
        case "fields" -> projectionProperties.put(name, fieldSchema);
        case "filter" ->
            publishedProperties.put(
                name, hasScanRange ? withoutLegacyRange(fieldSchema) : fieldSchema);
        default -> publishedProperties.put(name, fieldSchema);
      }
    }
    if (!pageProperties.isEmpty()) {
      publishedProperties.put("page", nestedObject(pageProperties));
    }
    if (!scanProperties.isEmpty()) {
      publishedProperties.put("scan", nestedObject(scanProperties));
    }
    if (!projectionProperties.isEmpty()) {
      publishedProperties.put("projection", nestedObject(projectionProperties));
    }

    Map<String, Object> result = new LinkedHashMap<>(internalSchema);
    result.put(ApiVocabulary.PROPERTIES, publishedProperties);
    Object rawRequired = internalSchema.get("required");
    if (rawRequired instanceof List<?> required) {
      List<String> translated =
          required.stream()
              .map(String::valueOf)
              .map(StrictObjectCodec::publishedContainer)
              .distinct()
              .toList();
      if (translated.isEmpty()) result.remove("required");
      else result.put("required", translated);
    }
    return Collections.unmodifiableMap(result);
  }

  private static Map<String, Object> normalize(Map<String, Object> published) {
    Map<String, Object> result = new LinkedHashMap<>();
    for (Map.Entry<String, Object> entry : published.entrySet()) {
      switch (entry.getKey()) {
        case "page", "scan", "projection" -> copyNested(result, entry.getValue());
        default -> result.put(entry.getKey(), entry.getValue());
      }
    }
    return result;
  }

  private static void copyNested(Map<String, Object> target, Object value) {
    if (!(value instanceof Map<?, ?> nested)) return;
    for (Map.Entry<?, ?> entry : nested.entrySet()) {
      target.put(String.valueOf(entry.getKey()), entry.getValue());
    }
  }

  @SuppressWarnings("unchecked")
  private static Object withoutLegacyRange(Object fieldSchema) {
    if (!(fieldSchema instanceof Map<?, ?> rawSchema)
        || !(rawSchema.get(ApiVocabulary.PROPERTIES) instanceof Map<?, ?> rawProperties)) {
      return fieldSchema;
    }
    Map<String, Object> properties = new LinkedHashMap<>((Map<String, Object>) rawProperties);
    properties.remove("start");
    properties.remove("end");
    Map<String, Object> schema = new LinkedHashMap<>((Map<String, Object>) rawSchema);
    schema.put(ApiVocabulary.PROPERTIES, properties);
    return schema;
  }

  private static Map<String, Object> nestedObject(Map<String, Object> properties) {
    Map<String, Object> schema = new LinkedHashMap<>();
    schema.put(ApiVocabulary.TYPE, ApiVocabulary.OBJECT);
    schema.put(ApiVocabulary.ADDITIONAL_PROPERTIES, false);
    schema.put(ApiVocabulary.PROPERTIES, properties);
    return schema;
  }

  private static String publishedContainer(String field) {
    return switch (field) {
      case "limit", "cursor" -> "page";
      case "range", "timeout_ms" -> "scan";
      case "fields" -> "projection";
      default -> field;
    };
  }
}
