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
    Map<String, Object> normalized =
        (Map<String, Object>) normalizeAllowed(value, rootFields(knownFields));
    return normalized;
  }

  static Map<String, Object> list(Page<?> page) {
    return list(page, null, null);
  }

  static Map<String, Object> list(
      Page<?> page, Set<String> selectedFields, Set<String> knownFields) {
    if (page == null) {
      throw new IllegalArgumentException("list results must be a Page: null");
    }
    Object items =
        selectedFields != null
            ? normalize(page.items(), ProjectionNode.fromFields(selectedFields))
            : normalizeAllowedList(page.items(), rootFields(knownFields));
    Map<String, Object> result = new LinkedHashMap<>();
    result.put(ApiVocabulary.ITEMS, items);
    if (page.nextCursor() != null) {
      result.put(ApiVocabulary.NEXT_CURSOR, page.nextCursor());
    }
    if (page.scanProgress() != null) {
      result.put(ApiVocabulary.SCAN, normalize(page.scanProgress(), ProjectionNode.ALL));
    }
    return result;
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
        result.put(component.wireKey(), normalize(componentValue, ProjectionNode.ALL));
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
    if (node.includeAll()) {
      Map<String, Object> result = new LinkedHashMap<>();
      for (Map.Entry<?, ?> entry : map.entrySet()) {
        if (entry.getValue() == null) continue;
        result.put(String.valueOf(entry.getKey()), normalize(entry.getValue(), ProjectionNode.ALL));
      }
      return result;
    }
    Map<String, Object> result = new LinkedHashMap<>();
    for (Map.Entry<String, ProjectionNode> selected : node.children().entrySet()) {
      String key = selected.getKey();
      Object rawValue = map.get(key);
      if (rawValue == null) continue;
      ProjectionNode childNode = selected.getValue();
      Object normalized = normalize(rawValue, childNode);
      if (!childNode.includeAll()
          && !(normalized instanceof Map<?, ?>)
          && !(normalized instanceof List<?>)) {
        continue;
      }
      result.put(key, normalized);
    }
    return result;
  }

  private static List<Object> normalizeAllowedList(Iterable<?> iterable, Set<String> allowedRoots) {
    List<Object> result = new ArrayList<>();
    for (Object item : iterable) {
      result.add(normalizeAllowed(item, allowedRoots));
    }
    return result;
  }

  private static Object normalizeAllowed(Object value, Set<String> allowedRoots) {
    if (allowedRoots == null) {
      return normalize(value, ProjectionNode.ALL);
    }
    if (value != null && value.getClass().isRecord()) {
      RecordMeta meta = RECORD_COMPONENTS.get(value.getClass());
      Map<String, Object> result = new LinkedHashMap<>();
      for (ComponentMeta component : meta.ordered()) {
        if (!allowedRoots.contains(component.wireKey())) continue;
        Object componentValue = invokeAccessor(component, value);
        if (componentValue == null) continue;
        result.put(component.wireKey(), normalize(componentValue, ProjectionNode.ALL));
      }
      return result;
    }
    if (value instanceof Map<?, ?> map) {
      Map<String, Object> result = new LinkedHashMap<>();
      for (Map.Entry<?, ?> entry : map.entrySet()) {
        if (entry.getValue() == null) continue;
        String key = String.valueOf(entry.getKey());
        if (allowedRoots.contains(key)) {
          result.put(key, normalize(entry.getValue(), ProjectionNode.ALL));
        }
      }
      return result;
    }
    return normalize(value, ProjectionNode.ALL);
  }

  private static Set<String> rootFields(Set<String> knownFields) {
    if (knownFields == null || knownFields.isEmpty()) {
      return null;
    }
    boolean hasDot = false;
    for (String field : knownFields) {
      if (field.indexOf('.') >= 0) {
        hasDot = true;
        break;
      }
    }
    if (!hasDot) {
      return knownFields;
    }
    Set<String> roots = new LinkedHashSet<>(knownFields.size());
    for (String field : knownFields) {
      int separator = field.indexOf('.');
      roots.add(separator < 0 ? field : field.substring(0, separator));
    }
    return roots;
  }

  static Map<String, Object> restrict(Map<String, Object> value, Set<String> fields) {
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
