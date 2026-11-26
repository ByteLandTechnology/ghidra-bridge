package app.byteland.ghidra.mcp;

import app.byteland.ghidra.api.ApiCatalog.MethodDescriptor;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;

/** Builds flat parameter schemas for MCP domain tools without union or reference keywords. */
final class McpParamsSchema {
  private static final int SINGLE_OPERATION_MAX_DEPTH = 4;
  private static final int SUMMARY_MAX_DEPTH = 2;
  private static final String DATA_TYPE_REF = "#/$defs/data_type_reference";

  private McpParamsSchema() {}

  static Map<String, Object> build(String domain, Collection<MethodDescriptor> operations) {
    List<MethodDescriptor> descriptors = List.copyOf(operations);
    int maxDepth =
        descriptors.size() == 1 && !"batch".equals(domain)
            ? SINGLE_OPERATION_MAX_DEPTH
            : SUMMARY_MAX_DEPTH;
    List<Map<String, Object>> flattened =
        descriptors.stream()
            .map(descriptor -> flatten(descriptor.inputSchema(), 0, maxDepth))
            .toList();
    Map<String, Object> merged =
        flattened.size() == 1 ? flattened.getFirst() : mergeSchemas(flattened);

    Map<String, Object> params = new LinkedHashMap<>();
    params.put("type", "object");
    params.put("description", "Parameters for the operation");
    params.put("additionalProperties", false);
    Object properties = merged.get("properties");
    params.put("properties", properties instanceof Map<?, ?> map ? map : Map.of());
    if (merged.get("required") instanceof List<?> required && !required.isEmpty()) {
      params.put("required", required);
    }
    return Collections.unmodifiableMap(params);
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> flatten(Map<String, Object> schema, int depth, int maxDepth) {
    if (schema.get("$ref") instanceof String reference) {
      return flattenReference(reference, depth, maxDepth);
    }
    List<Map<String, Object>> unionBranches = unionBranches(schema);
    if (unionBranches != null) {
      List<Map<String, Object>> nonNull =
          unionBranches.stream()
              .filter(branch -> !"null".equals(branch.get("type")))
              .map(branch -> flatten(branch, depth, maxDepth))
              .toList();
      if (nonNull.isEmpty()) {
        return Map.of();
      }
      return nonNull.size() == 1 ? nonNull.getFirst() : mergeSchemas(nonNull);
    }
    Object rawType = schema.get("type");
    if (!(rawType instanceof String type)) {
      return copyDescriptionOnly(schema);
    }
    return switch (type) {
      case "object" -> flattenObject(schema, depth, maxDepth);
      case "array" -> flattenArray(schema, depth, maxDepth);
      case "string", "integer", "number", "boolean" -> flattenScalar(schema, type);
      default -> Map.of("type", type);
    };
  }

  private static Map<String, Object> flattenReference(String reference, int depth, int maxDepth) {
    if (!DATA_TYPE_REF.equals(reference) || depth >= maxDepth) {
      return Map.of("type", "object");
    }
    Map<String, Object> properties = new LinkedHashMap<>();
    properties.put(
        "kind",
        Map.of("type", "string", "enum", List.of("array", "named", "pointer", "untyped_pointer")));
    properties.put("name", Map.of("type", "string", "minLength", 1));
    properties.put("target", flattenReference(reference, depth + 1, maxDepth));
    properties.put("element", flattenReference(reference, depth + 1, maxDepth));
    properties.put("count", Map.of("type", "integer", "minimum", 1, "maximum", Integer.MAX_VALUE));

    Map<String, Object> result = new LinkedHashMap<>();
    result.put("type", "object");
    result.put("additionalProperties", false);
    result.put("properties", Collections.unmodifiableMap(properties));
    result.put("required", List.of("kind"));
    return Collections.unmodifiableMap(result);
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> flattenObject(
      Map<String, Object> schema, int depth, int maxDepth) {
    if (Boolean.TRUE.equals(schema.get("additionalProperties"))
        || !(schema.get("properties") instanceof Map<?, ?> rawProperties)) {
      return withDescription(Map.of("type", "object"), schema);
    }
    if (depth >= maxDepth) {
      if (rawProperties.isEmpty()) {
        Map<String, Object> empty = new LinkedHashMap<>();
        empty.put("type", "object");
        empty.put("additionalProperties", false);
        empty.put("properties", Map.of());
        return Collections.unmodifiableMap(withDescription(empty, schema));
      }
      return withDescription(Map.of("type", "object"), schema);
    }
    Map<String, Object> properties = new LinkedHashMap<>();
    for (Map.Entry<?, ?> entry : rawProperties.entrySet()) {
      String key = String.valueOf(entry.getKey());
      Map<String, Object> child = (Map<String, Object>) entry.getValue();
      properties.put(key, flatten(child, depth + 1, maxDepth));
    }
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("type", "object");
    copyIfPresent(schema, result, "description");
    result.put("additionalProperties", false);
    result.put("properties", Collections.unmodifiableMap(properties));
    copyIfPresent(schema, result, "minProperties");
    copyIfPresent(schema, result, "maxProperties");
    if (schema.get("required") instanceof List<?> required && !required.isEmpty()) {
      result.put("required", List.copyOf(required));
    }
    return Collections.unmodifiableMap(result);
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> flattenArray(
      Map<String, Object> schema, int depth, int maxDepth) {
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("type", "array");
    copyIfPresent(schema, result, "description");
    if (schema.get("items") instanceof Map<?, ?> itemSchema) {
      result.put("items", flatten((Map<String, Object>) itemSchema, depth, maxDepth));
    }
    copyIfPresent(schema, result, "minItems");
    copyIfPresent(schema, result, "maxItems");
    return Collections.unmodifiableMap(result);
  }

  private static Map<String, Object> flattenScalar(Map<String, Object> schema, String type) {
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("type", type);
    for (String key :
        List.of(
            "description",
            "enum",
            "minLength",
            "maxLength",
            "pattern",
            "minimum",
            "maximum",
            "default")) {
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

  @SuppressWarnings("unchecked")
  private static Map<String, Object> mergeObjects(List<Map<String, Object>> schemas) {
    boolean allClosed =
        schemas.stream()
            .allMatch(schema ->
                Boolean.FALSE.equals(schema.get("additionalProperties"))
                    && schema.get("properties") instanceof Map<?, ?>);
    if (!allClosed) {
      return Map.of("type", "object");
    }
    Map<String, List<Map<String, Object>>> propertyBuckets = new LinkedHashMap<>();
    for (Map<String, Object> schema : schemas) {
      Map<String, Object> properties = (Map<String, Object>) schema.get("properties");
      properties.forEach((key, child) ->
          propertyBuckets
              .computeIfAbsent(key, ignored -> new ArrayList<>())
              .add((Map<String, Object>) child));
    }
    Map<String, Object> mergedProperties = new LinkedHashMap<>();
    propertyBuckets.forEach((key, bucket) ->
        mergedProperties.put(key, bucket.size() == 1 ? bucket.getFirst() : mergeSchemas(bucket)));

    Set<String> requiredIntersection = null;
    for (Map<String, Object> schema : schemas) {
      Set<String> branchRequired = new LinkedHashSet<>();
      if (schema.get("required") instanceof List<?> list) {
        list.forEach(item -> branchRequired.add(String.valueOf(item)));
      }
      if (requiredIntersection == null) {
        requiredIntersection = branchRequired;
      } else {
        requiredIntersection.retainAll(branchRequired);
      }
    }

    Map<String, Object> result = new LinkedHashMap<>();
    result.put("type", "object");
    putSharedScalar(schemas, result, "description");
    result.put("additionalProperties", false);
    result.put("properties", Collections.unmodifiableMap(mergedProperties));
    putMergedBound(schemas, result, "minProperties", true);
    putMergedBound(schemas, result, "maxProperties", false);
    if (requiredIntersection != null && !requiredIntersection.isEmpty()) {
      result.put("required", List.copyOf(requiredIntersection));
    }
    return Collections.unmodifiableMap(result);
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> mergeArrays(List<Map<String, Object>> schemas) {
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("type", "array");
    putSharedScalar(schemas, result, "description");
    List<Map<String, Object>> itemSchemas = new ArrayList<>();
    for (Map<String, Object> schema : schemas) {
      if (schema.get("items") instanceof Map<?, ?> items) {
        itemSchemas.add((Map<String, Object>) items);
      }
    }
    if (!itemSchemas.isEmpty()) {
      result.put(
          "items", itemSchemas.size() == 1 ? itemSchemas.getFirst() : mergeSchemas(itemSchemas));
    }
    putMergedBound(schemas, result, "minItems", true);
    putMergedBound(schemas, result, "maxItems", false);
    return Collections.unmodifiableMap(result);
  }

  private static Map<String, Object> mergeStrings(List<Map<String, Object>> schemas) {
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("type", "string");
    putSharedScalar(schemas, result, "description");
    if (schemas.stream().allMatch(schema -> schema.get("enum") instanceof List<?>)) {
      Set<String> values = new TreeSet<>();
      for (Map<String, Object> schema : schemas) {
        ((List<?>) schema.get("enum")).forEach(item -> values.add(String.valueOf(item)));
      }
      result.put("enum", List.copyOf(values));
    }
    putMergedBound(schemas, result, "minLength", true);
    putMergedBound(schemas, result, "maxLength", false);
    putSharedScalar(schemas, result, "pattern");
    putSharedScalar(schemas, result, "default");
    return Collections.unmodifiableMap(result);
  }

  private static Map<String, Object> mergeNumbers(List<Map<String, Object>> schemas, String type) {
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("type", type);
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

  @SuppressWarnings("unchecked")
  private static List<Map<String, Object>> unionBranches(Map<String, Object> schema) {
    for (String keyword : List.of("oneOf", "anyOf", "allOf")) {
      if (schema.get(keyword) instanceof List<?> list) {
        List<Map<String, Object>> branches = new ArrayList<>(list.size());
        for (Object item : list) {
          if (item instanceof Map<?, ?> branch) {
            branches.add((Map<String, Object>) branch);
          }
        }
        return branches;
      }
    }
    return null;
  }

  private static String commonType(List<Map<String, Object>> schemas) {
    String first = null;
    for (Map<String, Object> schema : schemas) {
      if (!(schema.get("type") instanceof String current)) {
        return null;
      }
      if (first == null) {
        first = current;
      } else if (!first.equals(current)) {
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
    Number merged = null;
    boolean hasDecimal = false;
    for (Map<String, Object> schema : schemas) {
      if (!(schema.get(key) instanceof Number number)) {
        return;
      }
      if (number instanceof Double || number instanceof Float) {
        hasDecimal = true;
      }
      if (merged == null) {
        merged = number;
      } else {
        double candidate = number.doubleValue();
        double current = merged.doubleValue();
        if ((takeMinimum && candidate < current) || (!takeMinimum && candidate > current)) {
          merged = number;
        }
      }
    }
    if (merged != null) {
      if (hasDecimal) {
        target.put(key, merged.doubleValue());
      } else {
        long value = merged.longValue();
        target.put(
            key, value >= Integer.MIN_VALUE && value <= Integer.MAX_VALUE ? (int) value : value);
      }
    }
  }

  private static void putSharedScalar(
      List<Map<String, Object>> schemas, Map<String, Object> target, String key) {
    Object shared = null;
    for (Map<String, Object> schema : schemas) {
      Object candidate = schema.get(key);
      if (candidate == null) {
        continue;
      }
      if (shared == null) {
        shared = candidate;
      } else if (!Objects.equals(shared, candidate)) {
        return;
      }
    }
    if (shared != null) {
      target.put(key, shared);
    }
  }

  private static Map<String, Object> copyDescriptionOnly(Map<String, Object> schema) {
    if (schema.get("description") instanceof String description) {
      return Map.of("description", description);
    }
    return Map.of();
  }

  private static Map<String, Object> withDescription(
      Map<String, Object> base, Map<String, Object> source) {
    if (!(source.get("description") instanceof String description)) {
      return base;
    }
    Map<String, Object> copy = new LinkedHashMap<>(base);
    copy.put("description", description);
    return Collections.unmodifiableMap(copy);
  }

  private static void copyIfPresent(
      Map<String, Object> source, Map<String, Object> target, String key) {
    Object value = source.get(key);
    if (value != null) {
      target.put(key, value);
    }
  }
}
