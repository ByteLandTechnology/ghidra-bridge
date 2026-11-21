package app.byteland.ghidra.api;

import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.function.VariableStorageReference;
import app.byteland.ghidra.service.memory.MemoryBlockResource;
import app.byteland.ghidra.service.program.AddressSpaceResource;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.RecordComponent;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

final class WireValues {
  private WireValues() {}

  static Map<String, Object> resource(Object value) {
    return resource(value, null);
  }

  static Map<String, Object> resource(Object value, Set<String> selectedFields) {
    ProjectionNode node =
        selectedFields == null ? ProjectionNode.ALL : ProjectionNode.fromFields(selectedFields);
    @SuppressWarnings("unchecked")
    Map<String, Object> normalized = (Map<String, Object>) normalize(value, node);
    return normalized;
  }

  static Map<String, Object> resourceAllowed(Object value, Set<String> knownFields) {
    @SuppressWarnings("unchecked")
    Map<String, Object> normalized = (Map<String, Object>) normalize(value, allowedNode(knownFields));
    return normalized;
  }

  static Map<String, Object> list(Object value, int limit) {
    return list(value, limit, null, null);
  }

  static Map<String, Object> list(
      Object value, int limit, Set<String> selectedFields, Set<String> knownFields) {
    if (value == null) {
      throw new IllegalArgumentException("list results must be a Page or a collection: null");
    }
    ProjectionNode itemNode =
        selectedFields != null ? ProjectionNode.fromFields(selectedFields) : allowedNode(knownFields);
    if (value instanceof Page<?> typedPage) {
      Map<String, Object> result = new LinkedHashMap<>();
      result.put(ApiVocabulary.ITEMS, normalize(typedPage.items(), itemNode));
      if (typedPage.nextCursor() != null) {
        result.put(ApiVocabulary.NEXT_CURSOR, typedPage.nextCursor());
      }
      if (typedPage.scanProgress() != null) {
        result.put(ApiVocabulary.SCAN, normalize(typedPage.scanProgress(), ProjectionNode.ALL));
      }
      return result;
    }
    if (value instanceof Iterable<?> || value.getClass().isArray()) {
      @SuppressWarnings("unchecked")
      List<Object> items = (List<Object>) normalize(value, itemNode);
      return new LinkedHashMap<>(Map.of(ApiVocabulary.ITEMS, items));
    }
    throw new IllegalArgumentException(
        "list results must be a Page or a collection: " + value.getClass().getName());
  }

  static Map<String, Object> memory(Object value) {
    return memory(value, null);
  }

  static Map<String, Object> memory(Object value, Set<String> selectedFields) {
    if (value != null && value.getClass().isRecord()) {
      return resource(value, selectedFields);
    }
    Map<String, Object> normalized = resource(value);
    Object data = normalized.get("bytes");
    Map<String, Object> bytes;
    if (data instanceof Map<?, ?> map) {
      @SuppressWarnings("unchecked")
      Map<String, Object> existing = (Map<String, Object>) map;
      bytes = existing;
    } else if (data instanceof String encoded) {
      bytes = new LinkedHashMap<>();
      bytes.put(ApiVocabulary.ENCODING, normalized.get(ApiVocabulary.ENCODING));
      bytes.put("data", encoded);
      bytes.put(ApiVocabulary.LENGTH, normalized.get(ApiVocabulary.LENGTH));
    } else {
      return selectedFields == null
          ? normalized
          : ProjectionNode.fromFields(selectedFields).projectMap(normalized);
    }
    Map<String, Object> result = new LinkedHashMap<>();
    Object address = normalized.get("address");
    result.put("address", address != null ? address : normalized.get("start"));
    result.put("bytes", bytes);
    return selectedFields == null
        ? result
        : ProjectionNode.fromFields(selectedFields).projectMap(result);
  }

  static Object normalize(Object value) {
    return normalize(value, ProjectionNode.ALL);
  }

  static Object normalize(Object value, ProjectionNode node) {
    ProjectionNode activeNode = node == null ? ProjectionNode.ALL : node;
    if (value instanceof Instant instant) return instant.toString();
    if (value instanceof DataTypeReference reference) {
      Map<String, Object> result = new LinkedHashMap<>();
      result.put(ApiVocabulary.KIND, reference.kind());
      switch (reference) {
        case DataTypeReference.Named named -> result.put("name", named.name());
        case DataTypeReference.Pointer pointer ->
            result.put("target", normalize(pointer.target(), ProjectionNode.ALL));
        case DataTypeReference.Array array -> {
          result.put("element", normalize(array.element(), ProjectionNode.ALL));
          result.put("count", array.count());
        }
        case DataTypeReference.UntypedPointer ignored -> {
        }
      }
      return activeNode.includeAll() ? result : activeNode.projectMap(result);
    }
    if (value instanceof VariableStorageReference storage) {
      Map<String, Object> result = new LinkedHashMap<>();
      result.put(ApiVocabulary.KIND, storage.kind());
      switch (storage) {
        case VariableStorageReference.Serialization serialization ->
            result.put("serialization", serialization.serialization());
        case VariableStorageReference.Register register ->
            result.put("register", register.register());
      }
      return activeNode.includeAll() ? result : activeNode.projectMap(result);
    }
    if (value != null && value.getClass().isRecord()) {
      return normalizeRecord(value, activeNode);
    }
    if (value instanceof Map<?, ?> map) {
      return normalizeMap(map, activeNode);
    }
    if (value instanceof Iterable<?> iterable) {
      List<Object> result = new ArrayList<>();
      for (Object item : iterable) {
        Object normalized = normalize(item, activeNode);
        if (activeNode.includeAll() || normalized instanceof Map<?, ?>) {
          result.add(normalized);
        }
      }
      return result;
    }
    if (value != null && value.getClass().isArray()) {
      List<Object> result = new ArrayList<>();
      for (int index = 0; index < java.lang.reflect.Array.getLength(value); index++) {
        Object normalized = normalize(java.lang.reflect.Array.get(value, index), activeNode);
        if (activeNode.includeAll() || normalized instanceof Map<?, ?>) {
          result.add(normalized);
        }
      }
      return result;
    }
    if (value instanceof Enum<?> enumValue) {
      return enumValue.name().toLowerCase(Locale.ROOT);
    }
    return value;
  }

  private static Map<String, Object> normalizeRecord(Object value, ProjectionNode node) {
    RecordMeta meta = RECORD_COMPONENTS.get(value.getClass());
    Map<String, Object> result = new LinkedHashMap<>();
    if (node.includeAll()) {
      for (ComponentMeta component : meta.ordered()) {
        Object componentValue = invokeAccessor(component, value);
        if (componentValue == null) continue;
        String key = component.wireKey();
        Object normalized = normalize(componentValue, ProjectionNode.ALL);
        if ("id".equals(key) && normalized instanceof Number) normalized = normalized.toString();
        result.put(key, normalized);
      }
      return result;
    }
    for (Map.Entry<String, ProjectionNode> entry : node.children().entrySet()) {
      String key = entry.getKey();
      ComponentMeta component = meta.byWireKey().get(key);
      if (component == null) continue;
      Object componentValue = invokeAccessor(component, value);
      if (componentValue == null) continue;
      ProjectionNode childNode = entry.getValue();
      Object normalized = normalize(componentValue, childNode);
      if (!childNode.includeAll()
          && !(normalized instanceof Map<?, ?>)
          && !(normalized instanceof List<?>)) {
        continue;
      }
      if ("id".equals(key) && normalized instanceof Number) normalized = normalized.toString();
      result.put(key, normalized);
    }
    return result;
  }

  private static Object invokeAccessor(ComponentMeta component, Object value) {
    try {
      return component.accessor().invoke(value);
    } catch (IllegalAccessException | InvocationTargetException exception) {
      throw new IllegalStateException(
          "unable to encode record component " + component.name(), exception);
    }
  }

  private static Map<String, Object> normalizeMap(Map<?, ?> map, ProjectionNode node) {
    Map<String, Object> matched = new LinkedHashMap<>();
    for (Map.Entry<?, ?> entry : map.entrySet()) {
      if (entry.getValue() == null) continue;
      String key = snakeCase(String.valueOf(entry.getKey()));
      ProjectionNode childNode = node.child(key);
      if (childNode == null) continue;
      Object normalized = normalize(entry.getValue(), childNode);
      if ("bytes".equals(key) && normalized instanceof String encoded) {
        String encoding =
            map.get(ApiVocabulary.ENCODING) instanceof String text
                ? text.toLowerCase(Locale.ROOT)
                : ApiVocabulary.HEX;
        Map<String, Object> byteMap =
            Map.of(
                ApiVocabulary.ENCODING,
                encoding,
                "data",
                encoded,
                ApiVocabulary.LENGTH,
                encodedLength(encoding, encoded));
        normalized = childNode.includeAll() ? byteMap : childNode.projectMap(byteMap);
      }
      if (!childNode.includeAll()
          && !(normalized instanceof Map<?, ?>)
          && !(normalized instanceof List<?>)) {
        continue;
      }
      if ("id".equals(key) && normalized instanceof Number) {
        normalized = normalized.toString();
      }
      if ((ApiVocabulary.KIND.equals(key)
              || "flow_override".equals(key)
              || "source_type".equals(key)
              || "default_flow_type".equals(key)
              || "flow_type".equals(key)
              || "type".equals(key)
              || "endian".equals(key))
          && normalized instanceof String text) {
        normalized = snakeCase(text).toLowerCase(Locale.ROOT);
      }
      if (key.endsWith("_at") && normalized instanceof Number epochMillis) {
        normalized = Instant.ofEpochMilli(epochMillis.longValue()).toString();
      }
      matched.put(key, normalized);
    }
    if (node.includeAll() || matched.size() <= 1) {
      return matched;
    }
    Map<String, Object> ordered = new LinkedHashMap<>(matched.size());
    for (String key : node.children().keySet()) {
      Object value = matched.get(key);
      if (value != null) {
        ordered.put(key, value);
      }
    }
    return ordered;
  }

  private static ProjectionNode allowedNode(Set<String> knownFields) {
    if (knownFields == null || knownFields.isEmpty()) {
      return ProjectionNode.ALL;
    }
    Map<String, ProjectionNode> children = new LinkedHashMap<>();
    for (String field : knownFields) {
      int separator = field.indexOf('.');
      String root = separator < 0 ? field : field.substring(0, separator);
      children.putIfAbsent(root, ProjectionNode.ALL);
    }
    return new ProjectionNode(false, children);
  }

  static Map<String, Object> restrict(Map<String, Object> value, java.util.Set<String> fields) {
    Set<String> roots = new LinkedHashSet<>();
    for (String field : fields) {
      int separator = field.indexOf('.');
      roots.add(separator < 0 ? field : field.substring(0, separator));
    }
    Map<String, Object> result = new LinkedHashMap<>();
    for (String root : roots) {
      if (value.containsKey(root)) result.put(root, value.get(root));
    }
    return result;
  }

  private static int encodedLength(String encoding, String data) {
    if (ApiVocabulary.BASE64.equals(encoding)) {
      try {
        return java.util.Base64.getDecoder().decode(data).length;
      } catch (IllegalArgumentException ignored) {
        return -1;
      }
    }
    return data.length() % 2 == 0 ? data.length() / 2 : -1;
  }

  private record ComponentMeta(String name, String wireKey, Method accessor) {}

  private record RecordMeta(List<ComponentMeta> ordered, Map<String, ComponentMeta> byWireKey) {}

  private static final Map<String, String> WIRE_KEY_OVERRIDES =
      Map.of(
          AddressSpaceResource.class.getSimpleName() + "#isDefault", "default",
          MemoryBlockResource.class.getSimpleName() + "#isVolatile", "volatile");

  private static final ClassValue<RecordMeta> RECORD_COMPONENTS =
      new ClassValue<>() {
        @Override
        protected RecordMeta computeValue(Class<?> type) {
          List<ComponentMeta> ordered = new ArrayList<>();
          Map<String, ComponentMeta> byWireKey = new LinkedHashMap<>();
          for (RecordComponent component : type.getRecordComponents()) {
            String override =
                WIRE_KEY_OVERRIDES.get(type.getSimpleName() + "#" + component.getName());
            String wireKey = override != null ? override : snakeCase(component.getName());
            ComponentMeta meta =
                new ComponentMeta(component.getName(), wireKey, component.getAccessor());
            ordered.add(meta);
            byWireKey.put(wireKey, meta);
          }
          return new RecordMeta(List.copyOf(ordered), Collections.unmodifiableMap(byWireKey));
        }
      };

  private static String snakeCase(String value) {
    StringBuilder result = new StringBuilder();
    for (int index = 0; index < value.length(); index++) {
      char ch = value.charAt(index);
      if (!Character.isLetterOrDigit(ch)) {
        if (!result.isEmpty() && result.charAt(result.length() - 1) != '_') result.append('_');
        continue;
      }
      if (Character.isUpperCase(ch)) {
        boolean previousLower = index > 0 && Character.isLowerCase(value.charAt(index - 1));
        boolean nextLower =
            index + 1 < value.length() && Character.isLowerCase(value.charAt(index + 1));
        boolean previousUpper = index > 0 && Character.isUpperCase(value.charAt(index - 1));
        if (!result.isEmpty()
            && result.charAt(result.length() - 1) != '_'
            && (previousLower || (previousUpper && nextLower))) result.append('_');
        result.append(Character.toLowerCase(ch));
      } else {
        result.append(ch);
      }
    }
    while (!result.isEmpty() && result.charAt(result.length() - 1) == '_') {
      result.deleteCharAt(result.length() - 1);
    }
    return result.toString();
  }
}
