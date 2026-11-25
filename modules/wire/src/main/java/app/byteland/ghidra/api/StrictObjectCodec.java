package app.byteland.ghidra.api;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

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
    materializeAndPrune(normalized, validationSchema, WireSchema.definitionsOf(validationSchema));
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
    for (Map.Entry<?, ?> entry : properties.entrySet()) {
      String name = String.valueOf(entry.getKey());
      Object fieldSchema = entry.getValue();
      switch (name) {
        case "limit", "cursor" -> pageProperties.put(name, fieldSchema);
        case "range", "timeout_ms" -> scanProperties.put(name, fieldSchema);
        case "fields" -> projectionProperties.put(name, fieldSchema);
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

  private static Map<String, Object> nestedObject(Map<String, Object> properties) {
    Map<String, Object> schema = new LinkedHashMap<>();
    schema.put(ApiVocabulary.TYPE, ApiVocabulary.OBJECT);
    schema.put(ApiVocabulary.ADDITIONAL_PROPERTIES, false);
    schema.put(ApiVocabulary.PROPERTIES, properties);
    return schema;
  }

  @SuppressWarnings(ApiVocabulary.UNCHECKED)
  private static void materializeAndPrune(
      Map<String, Object> target,
      Map<String, Object> rawSchema,
      Map<String, Map<String, Object>> definitions) {
    Map<String, Object> schema = WireSchema.dereference(rawSchema, definitions);
    Map<String, Object> taggedBranch = WireSchema.selectTaggedBranch(schema, target);
    if (taggedBranch != null) {
      materializeAndPrune(target, taggedBranch, definitions);
    }
    if (!(schema.get(ApiVocabulary.PROPERTIES) instanceof Map<?, ?> properties)) {
      return;
    }
    Set<String> required = requiredFields(schema);
    for (Map.Entry<?, ?> entry : properties.entrySet()) {
      String key = String.valueOf(entry.getKey());
      if (!(entry.getValue() instanceof Map<?, ?> childRaw)) {
        continue;
      }
      Map<String, Object> propSchema =
          WireSchema.dereference((Map<String, Object>) childRaw, definitions);
      if (target.containsKey(key)) {
        Object current = target.get(key);
        if (current instanceof Map<?, ?> nestedMap) {
          Map<String, Object> mutableChild = copyMap(nestedMap);
          materializeAndPrune(mutableChild, propSchema, definitions);
          if (mutableChild.isEmpty() && canPruneEmptyObject(propSchema, required.contains(key))) {
            target.remove(key);
          } else {
            target.put(key, Collections.unmodifiableMap(mutableChild));
          }
        } else if (current instanceof List<?> nestedList) {
          target.put(key, normalizeList(nestedList, propSchema, definitions));
        }
      } else if (propSchema.containsKey(ApiVocabulary.DEFAULT)) {
        target.put(key, immutableDefault(propSchema.get(ApiVocabulary.DEFAULT)));
      } else if (canSynthesizeDefaultObject(propSchema, required.contains(key))) {
        Map<String, Object> candidate = new LinkedHashMap<>();
        materializeAndPrune(candidate, propSchema, definitions);
        if (!candidate.isEmpty()) {
          target.put(key, Collections.unmodifiableMap(candidate));
        }
      }
    }
  }

  @SuppressWarnings(ApiVocabulary.UNCHECKED)
  private static List<Object> normalizeList(
      List<?> source,
      Map<String, Object> arraySchema,
      Map<String, Map<String, Object>> definitions) {
    Object rawItems = arraySchema.get(ApiVocabulary.ITEMS);
    if (!(rawItems instanceof Map<?, ?> itemSchemaRaw)) {
      return List.copyOf(source);
    }
    Map<String, Object> itemSchema =
        WireSchema.dereference((Map<String, Object>) itemSchemaRaw, definitions);
    List<Object> result = new ArrayList<>(source.size());
    for (Object item : source) {
      if (item instanceof Map<?, ?> itemMap) {
        Map<String, Object> mutableItem = copyMap(itemMap);
        materializeAndPrune(mutableItem, itemSchema, definitions);
        result.add(Collections.unmodifiableMap(mutableItem));
      } else {
        result.add(item);
      }
    }
    return Collections.unmodifiableList(result);
  }

  private static boolean canPruneEmptyObject(Map<String, Object> propSchema, boolean isRequired) {
    return !isRequired
        && ApiVocabulary.OBJECT.equals(propSchema.get(ApiVocabulary.TYPE))
        && !Boolean.TRUE.equals(propSchema.get(ApiVocabulary.ADDITIONAL_PROPERTIES));
  }

  private static boolean canSynthesizeDefaultObject(
      Map<String, Object> propSchema, boolean isRequired) {
    return !isRequired
        && ApiVocabulary.OBJECT.equals(propSchema.get(ApiVocabulary.TYPE))
        && requiredFields(propSchema).isEmpty()
        && ((Number) propSchema.getOrDefault(ApiVocabulary.MIN_PROPERTIES, 0)).intValue() == 0
        && propSchema.get(ApiVocabulary.ONE_OF) == null;
  }

  private static Set<String> requiredFields(Map<String, Object> schema) {
    if (!(schema.get(ApiVocabulary.REQUIRED) instanceof List<?> required)) {
      return Set.of();
    }
    Set<String> names = new LinkedHashSet<>(required.size());
    for (Object name : required) {
      names.add(String.valueOf(name));
    }
    return names;
  }

  private static Map<String, Object> copyMap(Map<?, ?> source) {
    Map<String, Object> copy = new LinkedHashMap<>();
    for (Map.Entry<?, ?> entry : source.entrySet()) {
      copy.put(String.valueOf(entry.getKey()), entry.getValue());
    }
    return copy;
  }

  private static Object immutableDefault(Object value) {
    if (value instanceof Map<?, ?> map) {
      Map<String, Object> copy = new LinkedHashMap<>();
      for (Map.Entry<?, ?> entry : map.entrySet()) {
        copy.put(String.valueOf(entry.getKey()), immutableDefault(entry.getValue()));
      }
      return Collections.unmodifiableMap(copy);
    }
    if (value instanceof List<?> list) {
      List<Object> copy = new ArrayList<>(list.size());
      for (Object item : list) {
        copy.add(immutableDefault(item));
      }
      return Collections.unmodifiableList(copy);
    }
    return value;
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
