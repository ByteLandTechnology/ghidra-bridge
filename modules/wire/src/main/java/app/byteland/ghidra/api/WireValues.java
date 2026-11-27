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
import java.util.Collection;
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
    @SuppressWarnings("unchecked")
    Map<String, Object> normalized = (Map<String, Object>) normalize(value);
    return normalized;
  }

  static Map<String, Object> resource(Object value, Set<String> selectedPaths) {
    return resource(value, FieldSelection.from(selectedPaths));
  }

  @SuppressWarnings("unchecked")
  static Map<String, Object> resource(Object value, FieldSelection selection) {
    return (Map<String, Object>)
        normalize(value, selection == null ? FieldSelection.ALL : selection);
  }

  @SuppressWarnings("unchecked")
  static Map<String, Object> resourceRestrictingRoots(Object value, Set<String> allowedRoots) {
    return (Map<String, Object>) normalizeRestrictingRoots(value, allowedRoots);
  }

  static Map<String, Object> list(Page<?> page) {
    return list(page, FieldSelection.ALL);
  }

  static Map<String, Object> list(Page<?> page, Set<String> selectedPaths) {
    return list(page, FieldSelection.from(selectedPaths));
  }

  static Map<String, Object> list(Page<?> page, FieldSelection selection) {
    if (page == null) {
      throw new IllegalArgumentException("list results must be a Page: null");
    }
    FieldSelection itemSelection = selection == null ? FieldSelection.ALL : selection;
    List<?> rawItems = page.items();
    List<Object> normalizedItems = new ArrayList<>(rawItems.size());
    if (itemSelection.selectsAll()) {
      for (Object item : rawItems) {
        normalizedItems.add(normalize(item));
      }
    } else {
      Class<?> cachedRecordType = null;
      ProjectedComponent[] cachedPlan = null;
      for (Object item : rawItems) {
        if (item != null && item.getClass().isRecord()) {
          Class<?> itemType = item.getClass();
          if (itemType != cachedRecordType) {
            cachedRecordType = itemType;
            cachedPlan = buildProjectedPlan(itemType, itemSelection);
          }
          normalizedItems.add(normalizeRecord(item, cachedPlan));
        } else {
          normalizedItems.add(normalize(item, itemSelection));
        }
      }
    }
    return buildPageEnvelope(page, normalizedItems);
  }

  static Map<String, Object> listRestrictingRoots(Page<?> page, Set<String> allowedRoots) {
    if (page == null) {
      throw new IllegalArgumentException("list results must be a Page: null");
    }
    List<?> rawItems = page.items();
    List<Object> normalizedItems = new ArrayList<>(rawItems.size());
    for (Object item : rawItems) {
      normalizedItems.add(normalizeRestrictingRoots(item, allowedRoots));
    }
    return buildPageEnvelope(page, normalizedItems);
  }

  private static Map<String, Object> buildPageEnvelope(Page<?> page, List<Object> normalizedItems) {
    Map<String, Object> result = LinkedHashMap.newLinkedHashMap(3);
    result.put(ApiVocabulary.ITEMS, normalizedItems);
    if (page.nextCursor() != null) {
      result.put(ApiVocabulary.NEXT_CURSOR, page.nextCursor());
    }
    if (page.scanProgress() != null) {
      result.put(ApiVocabulary.SCAN, normalize(page.scanProgress()));
    }
    return result;
  }

  static Object normalize(Object value) {
    if (value instanceof Instant instant) return instant.toString();
    if (value instanceof DataTypeReference reference) {
      Map<String, Object> result = LinkedHashMap.newLinkedHashMap(3);
      result.put(ApiVocabulary.KIND, reference.kind());
      switch (reference) {
        case DataTypeReference.Named named -> result.put("name", named.name());
        case DataTypeReference.Pointer pointer -> result.put("target", normalize(pointer.target()));
        case DataTypeReference.Array array -> {
          result.put("element", normalize(array.element()));
          result.put("count", array.count());
        }
        case DataTypeReference.UntypedPointer ignored -> {}
      }
      return result;
    }
    if (value instanceof VariableStorageReference storage) {
      Map<String, Object> result = LinkedHashMap.newLinkedHashMap(2);
      result.put(ApiVocabulary.KIND, storage.kind());
      switch (storage) {
        case VariableStorageReference.Serialization serialization ->
            result.put("serialization", serialization.serialization());
        case VariableStorageReference.Register register ->
            result.put("register", register.register());
      }
      return result;
    }
    if (value != null && value.getClass().isRecord()) {
      ComponentMeta[] components = RECORD_COMPONENTS.get(value.getClass()).ordered();
      Map<String, Object> result = LinkedHashMap.newLinkedHashMap(components.length);
      for (ComponentMeta component : components) {
        Object componentValue = invokeAccessor(component, value);
        if (componentValue == null) continue;
        result.put(component.wireKey(), normalize(componentValue));
      }
      return result;
    }
    if (value instanceof Map<?, ?> map) {
      Map<String, Object> result = LinkedHashMap.newLinkedHashMap(map.size());
      for (Map.Entry<?, ?> entry : map.entrySet()) {
        if (entry.getValue() == null) continue;
        result.put(String.valueOf(entry.getKey()), normalize(entry.getValue()));
      }
      return result;
    }
    if (value instanceof Iterable<?> iterable) {
      List<Object> result =
          iterable instanceof Collection<?> c ? new ArrayList<>(c.size()) : new ArrayList<>();
      for (Object item : iterable) result.add(normalize(item));
      return result;
    }
    if (value instanceof Enum<?> enumValue) {
      return enumValue.name().toLowerCase(Locale.ROOT);
    }
    return value;
  }

  static Object normalize(Object value, Set<String> selectedPaths) {
    return normalize(value, FieldSelection.from(selectedPaths));
  }

  static Object normalize(Object value, FieldSelection selection) {
    if (selection == null || selection.selectsAll()) {
      return normalize(value);
    }
    if (value == null) {
      return null;
    }
    if (value instanceof DataTypeReference reference) {
      return normalizeDataTypeReference(reference, selection);
    }
    if (value instanceof VariableStorageReference storage) {
      return normalizeStorageReference(storage, selection);
    }
    if (value.getClass().isRecord()) {
      Map<String, ComponentMeta> byWireKey = RECORD_COMPONENTS.get(value.getClass()).byWireKey();
      FieldSelection.Entry[] entries = selection.entries();
      Map<String, Object> result = LinkedHashMap.newLinkedHashMap(entries.length);
      for (FieldSelection.Entry entry : entries) {
        ComponentMeta component = byWireKey.get(entry.key());
        if (component == null) continue;
        Object componentValue = invokeAccessor(component, value);
        if (componentValue == null) continue;
        putProjectedValue(result, entry.key(), componentValue, entry.selection());
      }
      return result;
    }
    if (value instanceof Map<?, ?> map) {
      FieldSelection.Entry[] entries = selection.entries();
      Map<String, Object> result = LinkedHashMap.newLinkedHashMap(entries.length);
      for (FieldSelection.Entry entry : entries) {
        Object entryValue = map.get(entry.key());
        if (entryValue == null) continue;
        putProjectedValue(result, entry.key(), entryValue, entry.selection());
      }
      return result;
    }
    if (value instanceof Iterable<?> iterable) {
      List<Object> result =
          iterable instanceof Collection<?> c ? new ArrayList<>(c.size()) : new ArrayList<>();
      for (Object item : iterable) {
        if (isObjectValue(item)) {
          result.add(normalize(item, selection));
        }
      }
      return result;
    }
    return normalize(value);
  }

  private static ProjectedComponent[] buildProjectedPlan(
      Class<?> recordType, FieldSelection selection) {
    Map<String, ComponentMeta> byWireKey = RECORD_COMPONENTS.get(recordType).byWireKey();
    FieldSelection.Entry[] entries = selection.entries();
    int matchCount = 0;
    for (FieldSelection.Entry entry : entries) {
      if (byWireKey.containsKey(entry.key())) {
        matchCount++;
      }
    }
    ProjectedComponent[] plan = new ProjectedComponent[matchCount];
    int index = 0;
    for (FieldSelection.Entry entry : entries) {
      ComponentMeta meta = byWireKey.get(entry.key());
      if (meta != null) {
        plan[index++] = new ProjectedComponent(entry.key(), meta, entry.selection());
      }
    }
    return plan;
  }

  private static Map<String, Object> normalizeRecord(
      Object recordValue, ProjectedComponent[] plan) {
    Map<String, Object> result = LinkedHashMap.newLinkedHashMap(plan.length);
    for (ProjectedComponent component : plan) {
      Object componentValue = invokeAccessor(component.meta(), recordValue);
      if (componentValue == null) continue;
      putProjectedValue(result, component.wireKey(), componentValue, component.childSelection());
    }
    return result;
  }

  private static Object normalizeRestrictingRoots(Object value, Set<String> allowedRoots) {
    if (allowedRoots == null || allowedRoots.isEmpty()) {
      return Map.of();
    }
    if (value != null && value.getClass().isRecord()) {
      ComponentMeta[] components = RECORD_COMPONENTS.get(value.getClass()).ordered();
      Map<String, Object> result = LinkedHashMap.newLinkedHashMap(components.length);
      for (ComponentMeta component : components) {
        if (!allowedRoots.contains(component.wireKey())) continue;
        Object componentValue = invokeAccessor(component, value);
        if (componentValue == null) continue;
        result.put(component.wireKey(), normalize(componentValue));
      }
      return result;
    }
    if (value instanceof Map<?, ?> map) {
      Map<String, Object> result = LinkedHashMap.newLinkedHashMap(map.size());
      for (Map.Entry<?, ?> entry : map.entrySet()) {
        if (entry.getValue() == null) continue;
        String key = String.valueOf(entry.getKey());
        if (!allowedRoots.contains(key)) continue;
        result.put(key, normalize(entry.getValue()));
      }
      return result;
    }
    return normalize(value);
  }

  private static Map<String, Object> normalizeDataTypeReference(
      DataTypeReference reference, FieldSelection selection) {
    FieldSelection.Entry[] entries = selection.entries();
    Map<String, Object> result = LinkedHashMap.newLinkedHashMap(entries.length);
    for (FieldSelection.Entry entry : entries) {
      String key = entry.key();
      FieldSelection childSelection = entry.selection();
      switch (key) {
        case ApiVocabulary.KIND -> result.put(ApiVocabulary.KIND, reference.kind());
        case "name" -> {
          if (reference instanceof DataTypeReference.Named named) {
            result.put("name", named.name());
          }
        }
        case "target" -> {
          if (reference instanceof DataTypeReference.Pointer pointer) {
            putProjectedValue(result, "target", pointer.target(), childSelection);
          }
        }
        case "element" -> {
          if (reference instanceof DataTypeReference.Array array) {
            putProjectedValue(result, "element", array.element(), childSelection);
          }
        }
        case "count" -> {
          if (reference instanceof DataTypeReference.Array array) {
            result.put("count", array.count());
          }
        }
        default -> {}
      }
    }
    return result;
  }

  private static Map<String, Object> normalizeStorageReference(
      VariableStorageReference storage, FieldSelection selection) {
    FieldSelection.Entry[] entries = selection.entries();
    Map<String, Object> result = LinkedHashMap.newLinkedHashMap(entries.length);
    for (FieldSelection.Entry entry : entries) {
      switch (entry.key()) {
        case ApiVocabulary.KIND -> result.put(ApiVocabulary.KIND, storage.kind());
        case "serialization" -> {
          if (storage instanceof VariableStorageReference.Serialization serialization) {
            result.put("serialization", serialization.serialization());
          }
        }
        case "register" -> {
          if (storage instanceof VariableStorageReference.Register register) {
            result.put("register", register.register());
          }
        }
        default -> {}
      }
    }
    return result;
  }

  private static void putProjectedValue(
      Map<String, Object> result, String key, Object rawValue, FieldSelection childSelection) {
    if (childSelection.selectsAll()) {
      result.put(key, normalize(rawValue));
      return;
    }
    if (isObjectValue(rawValue) || rawValue instanceof Iterable<?>) {
      result.put(key, normalize(rawValue, childSelection));
    }
  }

  private static boolean isObjectValue(Object value) {
    return value != null
        && (value.getClass().isRecord()
            || value instanceof Map<?, ?>
            || value instanceof DataTypeReference
            || value instanceof VariableStorageReference);
  }

  private static Object invokeAccessor(ComponentMeta component, Object recordInstance) {
    try {
      return component.accessor().invoke(recordInstance);
    } catch (IllegalAccessException | InvocationTargetException exception) {
      throw new IllegalStateException(
          "unable to encode record component " + component.name(), exception);
    }
  }

  static Set<String> rootFields(Set<String> fields) {
    Set<String> roots = new LinkedHashSet<>();
    for (String field : fields) {
      int separator = field.indexOf('.');
      roots.add(separator < 0 ? field : field.substring(0, separator));
    }
    return Collections.unmodifiableSet(roots);
  }

  static Map<String, Object> restrict(Map<String, Object> value, Set<String> fields) {
    Set<String> roots = rootFields(fields);
    Map<String, Object> result = new LinkedHashMap<>();
    for (String root : roots) {
      if (value.containsKey(root)) result.put(root, value.get(root));
    }
    return result;
  }

  private record ComponentMeta(String name, String wireKey, Method accessor) {}

  private record ProjectedComponent(
      String wireKey, ComponentMeta meta, FieldSelection childSelection) {}

  private record RecordMeta(ComponentMeta[] ordered, Map<String, ComponentMeta> byWireKey) {}

  private static final Map<String, String> WIRE_KEY_OVERRIDES =
      Map.of(
          AddressSpaceResource.class.getSimpleName() + "#isDefault", "default",
          MemoryBlockResource.class.getSimpleName() + "#isVolatile", "volatile");

  private static final ClassValue<RecordMeta> RECORD_COMPONENTS =
      new ClassValue<>() {
        @Override
        protected RecordMeta computeValue(Class<?> type) {
          RecordComponent[] raw = type.getRecordComponents();
          ComponentMeta[] ordered = new ComponentMeta[raw.length];
          Map<String, ComponentMeta> byWireKey = LinkedHashMap.newLinkedHashMap(raw.length);
          for (int index = 0; index < raw.length; index++) {
            RecordComponent component = raw[index];
            String override =
                WIRE_KEY_OVERRIDES.get(type.getSimpleName() + "#" + component.getName());
            String wireKey = override != null ? override : snakeCase(component.getName());
            ComponentMeta meta =
                new ComponentMeta(component.getName(), wireKey, component.getAccessor());
            ordered[index] = meta;
            byWireKey.put(wireKey, meta);
          }
          return new RecordMeta(ordered, Collections.unmodifiableMap(byWireKey));
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
