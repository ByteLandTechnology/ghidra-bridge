package app.byteland.ghidra.mcp;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

/**
 * Builds provider-safe JSON Schemas for MCP {@code tools/list} declarations by flattening each
 * operation input schema to depth 4 and omitting {@code oneOf}, {@code anyOf}, {@code allOf},
 * {@code $ref}, {@code $defs}, and {@code additionalProperties} at every depth.
 */
final class McpSchemaFlattener {
  static final int OPERATION_MAX_DEPTH = 4;

  private static final String DATA_TYPE_REF = "#/$defs/data_type_reference";
  private static final List<String> SCALAR_KEYS =
      List.of(
          "description",
          "enum",
          "minLength",
          "maxLength",
          "pattern",
          "minimum",
          "maximum",
          "default");

  private McpSchemaFlattener() {}

  static Map<String, Object> flattenOperationSchema(Map<String, Object> schema) {
    Objects.requireNonNull(schema, "schema");
    Map<String, Object> flattened = flatten(schema, 0, OPERATION_MAX_DEPTH);
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("type", "object");
    copyIfPresent(flattened, result, "description");
    Object rawProperties = flattened.get("properties");
    if (rawProperties instanceof Map<?, ?> properties) {
      result.put("properties", stringKeyMap(properties));
    } else {
      result.put("properties", Map.of());
    }
    copyIfPresent(flattened, result, "minProperties");
    copyIfPresent(flattened, result, "maxProperties");
    if (flattened.get("required") instanceof List<?> required && !required.isEmpty()) {
      result.put("required", List.copyOf(required));
    }
    return Collections.unmodifiableMap(result);
  }

  private static Map<String, Object> flatten(Map<?, ?> schema, int depth, int maxDepth) {
    if (schema.get("$ref") instanceof String reference) {
      return flattenReference(reference, depth, maxDepth);
    }
    List<Map<?, ?>> branches = unionBranches(schema);
    if (branches != null) {
      List<Map<String, Object>> nonNull = new ArrayList<>();
      for (Map<?, ?> branch : branches) {
        if (!"null".equals(branch.get("type"))) {
          nonNull.add(flatten(branch, depth, maxDepth));
        }
      }
      if (nonNull.isEmpty()) {
        return Map.of();
      }
      if (nonNull.size() == 1) {
        return nonNull.get(0);
      }
      return mergeSchemas(nonNull);
    }
    if (!(schema.get("type") instanceof String schemaType)) {
      return copyDescriptionOnly(schema);
    }
    return switch (schemaType) {
      case "object" -> flattenObject(schema, depth, maxDepth);
      case "array" -> flattenArray(schema, depth, maxDepth);
      case "string", "integer", "number", "boolean" -> flattenScalar(schema, schemaType);
      default -> Map.of("type", schemaType);
    };
  }

  private static Map<String, Object> flattenReference(String reference, int depth, int maxDepth) {
    if (!DATA_TYPE_REF.equals(reference) || depth >= maxDepth) {
      return Map.of("type", "object");
    }
    Map<String, Object> properties = new LinkedHashMap<>();
    properties.put(
        "kind",
        orderedMap(
            "type", "string", "enum", List.of("array", "named", "pointer", "untyped_pointer")));
    properties.put("name", orderedMap("type", "string", "minLength", 1));
    properties.put("target", flattenReference(reference, depth + 1, maxDepth));
    properties.put("element", flattenReference(reference, depth + 1, maxDepth));
    properties.put("count", orderedMap("type", "integer", "minimum", 1, "maximum", Integer.MAX_VALUE));
    return orderedMap(
        "type",
        "object",
        "properties",
        Collections.unmodifiableMap(properties),
        "required",
        List.of("kind"));
  }

  private static Map<String, Object> flattenObject(Map<?, ?> schema, int depth, int maxDepth) {
    if (Boolean.TRUE.equals(schema.get("additionalProperties"))) {
      return withDescription(Map.of("type", "object"), schema);
    }
    if (!(schema.get("properties") instanceof Map<?, ?> rawProperties)) {
      return withDescription(Map.of("type", "object"), schema);
    }
    if (depth >= maxDepth) {
      if (rawProperties.isEmpty()) {
        return withDescription(orderedMap("type", "object", "properties", Map.of()), schema);
      }
      return withDescription(Map.of("type", "object"), schema);
    }
    Map<String, Object> properties = new LinkedHashMap<>();
    for (Map.Entry<?, ?> entry : rawProperties.entrySet()) {
      if (entry.getKey() instanceof String key && entry.getValue() instanceof Map<?, ?> child) {
        properties.put(key, flatten(child, depth + 1, maxDepth));
      }
    }
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("type", "object");
    copyIfPresent(schema, result, "description");
    result.put("properties", Collections.unmodifiableMap(properties));
    copyIfPresent(schema, result, "minProperties");
    copyIfPresent(schema, result, "maxProperties");
    if (schema.get("required") instanceof List<?> required && !required.isEmpty()) {
      result.put("required", List.copyOf(required));
    }
    return Collections.unmodifiableMap(result);
  }

  private static Map<String, Object> flattenArray(Map<?, ?> schema, int depth, int maxDepth) {
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("type", "array");
    copyIfPresent(schema, result, "description");
    if (schema.get("items") instanceof Map<?, ?> items) {
      result.put("items", flatten(items, depth, maxDepth));
    }
    copyIfPresent(schema, result, "minItems");
    copyIfPresent(schema, result, "maxItems");
    return Collections.unmodifiableMap(result);
  }

  private static Map<String, Object> flattenScalar(Map<?, ?> schema, String schemaType) {
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("type", schemaType);
    for (String key : SCALAR_KEYS) {
      copyIfPresent(schema, result, key);
    }
    return Collections.unmodifiableMap(result);
  }

  private static Map<String, Object> mergeSchemas(List<Map<String, Object>> schemas) {
    String commonType = commonType(schemas);
    if (commonType == null) {
      return Map.of();
    }
    return switch (commonType) {
      case "object" -> mergeObjects(schemas);
      case "array" -> mergeArrays(schemas);
      case "string" -> mergeStrings(schemas);
      case "integer", "number" -> mergeNumbers(schemas, commonType);
      case "boolean" -> mergeBooleans(schemas);
      default -> Map.of("type", commonType);
    };
  }

  private static Map<String, Object> mergeObjects(List<Map<String, Object>> schemas) {
    for (Map<String, Object> schema : schemas) {
      if (!(schema.get("properties") instanceof Map<?, ?>)) {
        return Map.of("type", "object");
      }
    }
    Set<String> keys = new LinkedHashSet<>();
    for (Map<String, Object> schema : schemas) {
      Map<?, ?> properties = (Map<?, ?>) schema.get("properties");
      for (Object key : properties.keySet()) {
        if (key instanceof String name) {
          keys.add(name);
        }
      }
    }
    Map<String, Object> mergedProperties = new LinkedHashMap<>();
    for (String key : keys) {
      List<Map<String, Object>> bucket = new ArrayList<>();
      for (Map<String, Object> schema : schemas) {
        Map<?, ?> properties = (Map<?, ?>) schema.get("properties");
        if (properties.get(key) instanceof Map<?, ?> child) {
          bucket.add(stringKeyMap(child));
        }
      }
      Map<String, Object> mergedChild =
          bucket.size() == 1 ? bucket.get(0) : mergeSchemas(bucket);
      mergedProperties.put(key, mergedChild);
    }

    List<String> required = intersectRequired(schemas);
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("type", "object");
    putSharedScalar(schemas, result, "description");
    result.put("properties", Collections.unmodifiableMap(mergedProperties));
    putMergedBound(schemas, result, "minProperties", true);
    putMergedBound(schemas, result, "maxProperties", false);
    if (!required.isEmpty()) {
      result.put("required", List.copyOf(required));
    }
    return Collections.unmodifiableMap(result);
  }

  private static List<String> intersectRequired(List<Map<String, Object>> schemas) {
    if (schemas.isEmpty()) {
      return List.of();
    }
    List<String> common = new ArrayList<>(requiredNames(schemas.get(0)));
    for (int index = 1; index < schemas.size(); index++) {
      Set<String> branch = new LinkedHashSet<>(requiredNames(schemas.get(index)));
      common.retainAll(branch);
    }
    return common;
  }

  private static List<String> requiredNames(Map<String, Object> schema) {
    if (!(schema.get("required") instanceof List<?> list)) {
      return List.of();
    }
    List<String> names = new ArrayList<>();
    for (Object item : list) {
      if (item instanceof String name) {
        names.add(name);
      }
    }
    return names;
  }

  private static Map<String, Object> mergeArrays(List<Map<String, Object>> schemas) {
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("type", "array");
    putSharedScalar(schemas, result, "description");
    List<Map<String, Object>> items = new ArrayList<>();
    for (Map<String, Object> schema : schemas) {
      if (schema.get("items") instanceof Map<?, ?> itemSchema) {
        items.add(stringKeyMap(itemSchema));
      }
    }
    if (!items.isEmpty()) {
      result.put("items", items.size() == 1 ? items.get(0) : mergeSchemas(items));
    }
    putMergedBound(schemas, result, "minItems", true);
    putMergedBound(schemas, result, "maxItems", false);
    return Collections.unmodifiableMap(result);
  }

  private static Map<String, Object> mergeStrings(List<Map<String, Object>> schemas) {
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("type", "string");
    putSharedScalar(schemas, result, "description");
    boolean allHaveEnum = true;
    for (Map<String, Object> schema : schemas) {
      if (!(schema.get("enum") instanceof List<?>)) {
        allHaveEnum = false;
        break;
      }
    }
    if (allHaveEnum) {
      Set<String> values = new TreeSet<>();
      for (Map<String, Object> schema : schemas) {
        List<?> items = (List<?>) schema.get("enum");
        for (Object item : items) {
          if (item instanceof String text) {
            values.add(text);
          }
        }
      }
      result.put("enum", List.copyOf(values));
    }
    putMergedBound(schemas, result, "minLength", true);
    putMergedBound(schemas, result, "maxLength", false);
    putSharedScalar(schemas, result, "pattern");
    putSharedScalar(schemas, result, "default");
    return Collections.unmodifiableMap(result);
  }

  private static Map<String, Object> mergeNumbers(
      List<Map<String, Object>> schemas, String schemaType) {
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("type", schemaType);
    putSharedScalar(schemas, result, "description");
    putMergedBound(schemas, result, "minimum", true);
    putMergedBound(schemas, result, "maximum", false);
    putSharedScalar(schemas, result, "default");
    return Collections.unmodifiableMap(result);
  }

  private static Map<String, Object> mergeBooleans(List<Map<String, Object>> schemas) {
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("type", "boolean");
    putSharedScalar(schemas, result, "description");
    putSharedScalar(schemas, result, "default");
    return Collections.unmodifiableMap(result);
  }

  private static List<Map<?, ?>> unionBranches(Map<?, ?> schema) {
    for (String keyword : List.of("oneOf", "anyOf", "allOf")) {
      if (schema.get(keyword) instanceof List<?> list) {
        List<Map<?, ?>> branches = new ArrayList<>();
        for (Object item : list) {
          if (item instanceof Map<?, ?> branch) {
            branches.add(branch);
          }
        }
        return branches;
      }
    }
    return null;
  }

  private static String commonType(List<Map<String, Object>> schemas) {
    if (schemas.isEmpty() || !(schemas.get(0).get("type") instanceof String first)) {
      return null;
    }
    for (Map<String, Object> schema : schemas) {
      if (!first.equals(schema.get("type"))) {
        return null;
      }
    }
    return first;
  }

  private static void putMergedBound(
      List<Map<String, Object>> schemas,
      Map<String, Object> target,
      String key,
      boolean takeMinimum) {
    Long intBound = null;
    Double floatBound = null;
    boolean isFloat = false;
    for (Map<String, Object> schema : schemas) {
      Object value = schema.get(key);
      if (!(value instanceof Number number)) {
        return;
      }
      if (value instanceof Double || value instanceof Float) {
        isFloat = true;
        double candidate = number.doubleValue();
        if (floatBound == null) {
          floatBound = intBound != null
              ? (takeMinimum ? Math.min(intBound, candidate) : Math.max(intBound, candidate))
              : candidate;
        } else {
          floatBound = takeMinimum ? Math.min(floatBound, candidate) : Math.max(floatBound, candidate);
        }
      } else {
        long candidate = number.longValue();
        if (isFloat) {
          floatBound = takeMinimum ? Math.min(floatBound, candidate) : Math.max(floatBound, candidate);
        } else {
          intBound =
              intBound == null
                  ? candidate
                  : (takeMinimum ? Math.min(intBound, candidate) : Math.max(intBound, candidate));
        }
      }
    }
    if (isFloat) {
      if (floatBound != null) {
        target.put(key, floatBound);
      }
    } else if (intBound != null) {
      if (intBound >= Integer.MIN_VALUE && intBound <= Integer.MAX_VALUE) {
        target.put(key, intBound.intValue());
      } else {
        target.put(key, intBound);
      }
    }
  }

  private static void putSharedScalar(
      List<Map<String, Object>> schemas, Map<String, Object> target, String key) {
    Object shared = null;
    boolean found = false;
    for (Map<String, Object> schema : schemas) {
      if (!schema.containsKey(key)) {
        continue;
      }
      Object candidate = schema.get(key);
      if (!found) {
        shared = candidate;
        found = true;
      } else if (!Objects.equals(shared, candidate)) {
        return;
      }
    }
    if (found) {
      target.put(key, shared);
    }
  }

  private static Map<String, Object> copyDescriptionOnly(Map<?, ?> schema) {
    Map<String, Object> result = new LinkedHashMap<>();
    copyIfPresent(schema, result, "description");
    return Collections.unmodifiableMap(result);
  }

  private static Map<String, Object> withDescription(Map<String, Object> base, Map<?, ?> source) {
    if (!source.containsKey("description")) {
      return base;
    }
    Map<String, Object> copy = new LinkedHashMap<>(base);
    copy.put("description", source.get("description"));
    return Collections.unmodifiableMap(copy);
  }

  private static void copyIfPresent(Map<?, ?> source, Map<String, Object> target, String key) {
    Object value = source.get(key);
    if (value != null) {
      target.put(key, value);
    }
  }

  private static Map<String, Object> stringKeyMap(Map<?, ?> raw) {
    Map<String, Object> copy = new LinkedHashMap<>();
    for (Map.Entry<?, ?> entry : raw.entrySet()) {
      if (entry.getKey() instanceof String key) {
        copy.put(key, entry.getValue());
      }
    }
    return Collections.unmodifiableMap(copy);
  }

  static Map<String, Object> orderedMap(Object... keyValues) {
    Map<String, Object> map = new LinkedHashMap<>();
    for (int index = 0; index < keyValues.length; index += 2) {
      map.put((String) keyValues[index], keyValues[index + 1]);
    }
    return Collections.unmodifiableMap(map);
  }
}
