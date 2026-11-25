package app.byteland.ghidra.mcp;

import app.byteland.ghidra.api.ApiCatalog.MethodDescriptor;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;

/**
 * Builds compact, provider-safe {@code params} schemas for MCP {@code tools/list}.
 *
 * <p>Public {@code tools/list} definitions omit {@code oneOf}, {@code anyOf}, {@code allOf},
 * {@code $ref}, {@code $defs}, and {@code additionalProperties} at every depth. Strict providers
 * then accept each tool declaration.
 */
final class McpSchemaBuilder {
  private static final int SINGLE_OPERATION_MAX_DEPTH = 4;
  private static final int SUMMARY_MAX_DEPTH = 2;
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

  private McpSchemaBuilder() {}

  static Map<String, Object> paramsSchema(
      String domainName, Map<String, MethodDescriptor> operations, String helpToolName) {
    int maxDepth =
        operations.size() == 1 && !"batch".equals(domainName)
            ? SINGLE_OPERATION_MAX_DEPTH
            : SUMMARY_MAX_DEPTH;
    List<Map<String, Object>> flattened =
        operations.values().stream()
            .map(operation -> flatten(operation.inputSchema(), 0, maxDepth))
            .toList();
    Map<String, Object> merged =
        flattened.size() == 1 ? flattened.getFirst() : mergeSchemas(flattened);

    String description =
        operations.size() == 1
            ? "The parameters for the operation."
            : multiOperationDescription(operations, helpToolName);

    Map<String, Object> params = new LinkedHashMap<>();
    params.put("type", "object");
    params.put("description", description);
    Object rawProps = merged.get("properties");
    Map<String, Object> properties =
        rawProps instanceof Map<?, ?> map ? copyStringMap(map) : Map.of();
    params.put("properties", properties);
    if (merged.get("required") instanceof List<?> required && !required.isEmpty()) {
      params.put("required", List.copyOf(required));
    }
    return Collections.unmodifiableMap(params);
  }

  private static String multiOperationDescription(
      Map<String, MethodDescriptor> operations, String helpToolName) {
    String requiredByOperation =
        operations.entrySet().stream()
            .map(entry -> formatOperationRequired(entry.getKey(), entry.getValue().inputSchema()))
            .collect(Collectors.joining("; "));
    return "The parameters summary for the tool. Required keys by operation: "
        + requiredByOperation
        + ". Call "
        + helpToolName
        + " with the domain for the exact schema of each operation.";
  }

  private static String formatOperationRequired(String operationName, Map<String, Object> schema) {
    List<String> keys = requiredStrings(schema);
    if (keys.isEmpty()) {
      return "`" + operationName + "` (none)";
    }
    String joined = keys.stream().map(key -> "`" + key + "`").collect(Collectors.joining(", "));
    return "`" + operationName + "` (" + joined + ")";
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> flatten(
      Map<String, Object> schema, int depth, int maxDepth) {
    if (schema.get("$ref") instanceof String reference) {
      return flattenReference(reference, depth, maxDepth);
    }
    List<Map<String, Object>> branches = unionBranches(schema);
    if (branches != null) {
      List<Map<String, Object>> nonNull =
          branches.stream()
              .filter(branch -> !"null".equals(branch.get("type")))
              .map(branch -> flatten(branch, depth, maxDepth))
              .toList();
      return switch (nonNull.size()) {
        case 0 -> Map.of();
        case 1 -> nonNull.getFirst();
        default -> mergeSchemas(nonNull);
      };
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

  private static Map<String, Object> flattenReference(
      String reference, int depth, int maxDepth) {
    if (!DATA_TYPE_REF.equals(reference) || depth >= maxDepth) {
      return Map.of("type", "object");
    }
    Map<String, Object> properties = new LinkedHashMap<>();
    properties.put(
        "kind",
        Map.of(
            "type",
            "string",
            "enum",
            List.of("array", "named", "pointer", "untyped_pointer")));
    properties.put("name", Map.of("type", "string", "minLength", 1));
    properties.put("target", flattenReference(reference, depth + 1, maxDepth));
    properties.put("element", flattenReference(reference, depth + 1, maxDepth));
    properties.put("count", Map.of("type", "integer", "minimum", 1, "maximum", Integer.MAX_VALUE));
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("type", "object");
    result.put("properties", Collections.unmodifiableMap(properties));
    result.put("required", List.of("kind"));
    return Collections.unmodifiableMap(result);
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> flattenObject(
      Map<String, Object> schema, int depth, int maxDepth) {
    if (Boolean.TRUE.equals(schema.get("additionalProperties"))) {
      return withDescription(Map.of("type", "object"), schema);
    }
    if (!(schema.get("properties") instanceof Map<?, ?> rawProperties)) {
      return withDescription(Map.of("type", "object"), schema);
    }
    if (depth >= maxDepth) {
      if (rawProperties.isEmpty()) {
        Map<String, Object> emptyObj = new LinkedHashMap<>();
        emptyObj.put("type", "object");
        emptyObj.put("properties", Map.of());
        return withDescription(Collections.unmodifiableMap(emptyObj), schema);
      }
      return withDescription(Map.of("type", "object"), schema);
    }
    Map<String, Object> properties = new LinkedHashMap<>();
    rawProperties.forEach(
        (key, child) ->
            properties.put(
                String.valueOf(key), flatten((Map<String, Object>) child, depth + 1, maxDepth)));
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("type", "object");
    copyIfPresent(schema, result, "description");
    result.put("properties", Collections.unmodifiableMap(properties));
    copyIfPresent(schema, result, "minProperties");
    copyIfPresent(schema, result, "maxProperties");
    List<String> required = requiredStrings(schema);
    if (!required.isEmpty()) {
      result.put("required", required);
    }
    return Collections.unmodifiableMap(result);
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> flattenArray(
      Map<String, Object> schema, int depth, int maxDepth) {
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("type", "array");
    copyIfPresent(schema, result, "description");
    if (schema.get("items") instanceof Map<?, ?> items) {
      result.put("items", flatten((Map<String, Object>) items, depth, maxDepth));
    }
    copyIfPresent(schema, result, "minItems");
    copyIfPresent(schema, result, "maxItems");
    return Collections.unmodifiableMap(result);
  }

  private static Map<String, Object> flattenScalar(
      Map<String, Object> schema, String schemaType) {
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

  @SuppressWarnings("unchecked")
  private static Map<String, Object> mergeObjects(List<Map<String, Object>> schemas) {
    for (Map<String, Object> schema : schemas) {
      if (!(schema.get("properties") instanceof Map<?, ?>)) {
        return Map.of("type", "object");
      }
    }
    List<String> keys = new ArrayList<>();
    for (Map<String, Object> schema : schemas) {
      Map<String, Object> properties = (Map<String, Object>) schema.get("properties");
      for (String key : properties.keySet()) {
        if (!keys.contains(key)) {
          keys.add(key);
        }
      }
    }
    Map<String, Object> mergedProperties = new LinkedHashMap<>();
    for (String key : keys) {
      List<Map<String, Object>> bucket = new ArrayList<>();
      for (Map<String, Object> schema : schemas) {
        Map<String, Object> properties = (Map<String, Object>) schema.get("properties");
        Object child = properties.get(key);
        if (child instanceof Map<?, ?> childMap) {
          bucket.add((Map<String, Object>) childMap);
        }
      }
      Map<String, Object> mergedChild =
          bucket.size() == 1 ? bucket.getFirst() : mergeSchemas(bucket);
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
      result.put("required", required);
    }
    return Collections.unmodifiableMap(result);
  }

  private static List<String> intersectRequired(List<Map<String, Object>> schemas) {
    if (schemas.isEmpty()) {
      return List.of();
    }
    List<String> common = new ArrayList<>(requiredStrings(schemas.getFirst()));
    for (int index = 1; index < schemas.size(); index++) {
      Set<String> branch = Set.copyOf(requiredStrings(schemas.get(index)));
      common.retainAll(branch);
    }
    return List.copyOf(common);
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> mergeArrays(List<Map<String, Object>> schemas) {
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("type", "array");
    putSharedScalar(schemas, result, "description");
    List<Map<String, Object>> items = new ArrayList<>();
    for (Map<String, Object> schema : schemas) {
      if (schema.get("items") instanceof Map<?, ?> itemMap) {
        items.add((Map<String, Object>) itemMap);
      }
    }
    if (!items.isEmpty()) {
      result.put("items", items.size() == 1 ? items.getFirst() : mergeSchemas(items));
    }
    putMergedBound(schemas, result, "minItems", true);
    putMergedBound(schemas, result, "maxItems", false);
    return Collections.unmodifiableMap(result);
  }

  private static Map<String, Object> mergeStrings(List<Map<String, Object>> schemas) {
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("type", "string");
    putSharedScalar(schemas, result, "description");
    boolean allEnums = schemas.stream().allMatch(schema -> schema.get("enum") instanceof List<?>);
    if (allEnums) {
      Set<String> values = new TreeSet<>();
      for (Map<String, Object> schema : schemas) {
        if (schema.get("enum") instanceof List<?> list) {
          for (Object item : list) {
            if (item instanceof String text) {
              values.add(text);
            }
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

  @SuppressWarnings("unchecked")
  private static List<Map<String, Object>> unionBranches(Map<String, Object> schema) {
    for (String keyword : List.of("oneOf", "anyOf", "allOf")) {
      if (schema.get(keyword) instanceof List<?> list) {
        List<Map<String, Object>> branches = new ArrayList<>(list.size());
        for (Object item : list) {
          if (item instanceof Map<?, ?> map) {
            branches.add((Map<String, Object>) map);
          }
        }
        return branches;
      }
    }
    return null;
  }

  private static String commonType(List<Map<String, Object>> schemas) {
    if (schemas.isEmpty() || !(schemas.getFirst().get("type") instanceof String first)) {
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
      Object raw = schema.get(key);
      if (!(raw instanceof Number number)) {
        return;
      }
      if (raw instanceof Double || raw instanceof Float) {
        isFloat = true;
        double candidate = number.doubleValue();
        double base = floatBound != null ? floatBound : (intBound != null ? intBound : candidate);
        floatBound = takeMinimum ? Math.min(base, candidate) : Math.max(base, candidate);
      } else {
        long candidate = number.longValue();
        if (isFloat) {
          double base = floatBound != null ? floatBound : candidate;
          floatBound = takeMinimum ? Math.min(base, candidate) : Math.max(base, candidate);
        } else {
          intBound =
              intBound == null
                  ? candidate
                  : (takeMinimum ? Math.min(intBound, candidate) : Math.max(intBound, candidate));
        }
      }
    }
    if (isFloat && floatBound != null) {
      target.put(key, floatBound);
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
    if (found && shared != null) {
      target.put(key, shared);
    }
  }

  private static List<String> requiredStrings(Map<String, Object> schema) {
    if (!(schema.get("required") instanceof List<?> list)) {
      return List.of();
    }
    List<String> keys = new ArrayList<>(list.size());
    for (Object item : list) {
      if (item instanceof String key) {
        keys.add(key);
      }
    }
    return List.copyOf(keys);
  }

  private static Map<String, Object> copyDescriptionOnly(Map<String, Object> schema) {
    Map<String, Object> result = new LinkedHashMap<>();
    copyIfPresent(schema, result, "description");
    return Collections.unmodifiableMap(result);
  }

  private static Map<String, Object> withDescription(
      Map<String, Object> base, Map<String, Object> source) {
    Object description = source.get("description");
    if (description == null) {
      return base;
    }
    Map<String, Object> result = new LinkedHashMap<>(base);
    result.put("description", description);
    return Collections.unmodifiableMap(result);
  }

  private static void copyIfPresent(
      Map<String, Object> source, Map<String, Object> target, String key) {
    Object value = source.get(key);
    if (value != null) {
      target.put(key, value);
    }
  }

  private static Map<String, Object> copyStringMap(Map<?, ?> raw) {
    Map<String, Object> copy = new LinkedHashMap<>();
    raw.forEach((key, value) -> copy.put(String.valueOf(key), value));
    return Collections.unmodifiableMap(copy);
  }
}
