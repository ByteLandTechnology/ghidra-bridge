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

  static Map<String, Object> list(Page<?> page) {
    if (page == null) {
      throw new IllegalArgumentException("list results must be a Page: null");
    }
    Map<String, Object> result = new LinkedHashMap<>();
    result.put(ApiVocabulary.ITEMS, normalize(page.items()));
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
      Map<String, Object> result = new LinkedHashMap<>();
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
      Map<String, Object> result = new LinkedHashMap<>();
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
      Map<String, Object> result = new LinkedHashMap<>();
      for (ComponentMeta component : RECORD_COMPONENTS.get(value.getClass())) {
        Object componentValue;
        try {
          componentValue = component.accessor().invoke(value);
        } catch (IllegalAccessException | InvocationTargetException exception) {
          throw new IllegalStateException(
              "unable to encode record component " + component.name(), exception);
        }
        if (componentValue == null) continue;
        result.put(component.wireKey(), normalize(componentValue));
      }
      return result;
    }
    if (value instanceof Map<?, ?> map) {
      Map<String, Object> result = new LinkedHashMap<>();
      for (Map.Entry<?, ?> entry : map.entrySet()) {
        if (entry.getValue() == null) continue;
        result.put(String.valueOf(entry.getKey()), normalize(entry.getValue()));
      }
      return result;
    }
    if (value instanceof Iterable<?> iterable) {
      List<Object> result = new ArrayList<>();
      for (Object item : iterable) result.add(normalize(item));
      return result;
    }
    if (value instanceof Enum<?> enumValue) {
      return enumValue.name().toLowerCase(Locale.ROOT);
    }
    return value;
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

  private static final Map<String, String> WIRE_KEY_OVERRIDES =
      Map.of(
          AddressSpaceResource.class.getSimpleName() + "#isDefault", "default",
          MemoryBlockResource.class.getSimpleName() + "#isVolatile", "volatile");

  private static final ClassValue<List<ComponentMeta>> RECORD_COMPONENTS =
      new ClassValue<>() {
        @Override
        protected List<ComponentMeta> computeValue(Class<?> type) {
          List<ComponentMeta> components = new ArrayList<>();
          for (RecordComponent component : type.getRecordComponents()) {
            String override =
                WIRE_KEY_OVERRIDES.get(type.getSimpleName() + "#" + component.getName());
            String wireKey = override != null ? override : snakeCase(component.getName());
            components.add(
                new ComponentMeta(component.getName(), wireKey, component.getAccessor()));
          }
          return List.copyOf(components);
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
