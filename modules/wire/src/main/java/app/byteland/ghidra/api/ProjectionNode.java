package app.byteland.ghidra.api;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Ordered field-projection tree built once from validated dot-path field names.
 */
record ProjectionNode(boolean includeAll, Map<String, ProjectionNode> children) {
  static final ProjectionNode ALL = new ProjectionNode(true, Map.of());

  ProjectionNode {
    children = children.isEmpty() ? Map.of() : Collections.unmodifiableMap(children);
  }

  static ProjectionNode fromFields(Set<String> fields) {
    if (fields == null) return null;
    Builder root = new Builder();
    for (String path : fields) {
      root.insert(path, 0);
    }
    return root.build();
  }

  ProjectionNode child(String key) {
    if (includeAll) return ALL;
    return children.get(key);
  }

  Object projectResponse(Object response) {
    if (!(response instanceof Map<?, ?> map)) {
      return response;
    }
    if (map.get(ApiVocabulary.ITEMS) instanceof List<?> items) {
      Map<String, Object> result = new LinkedHashMap<>();
      for (Map.Entry<?, ?> entry : map.entrySet()) {
        result.put(String.valueOf(entry.getKey()), entry.getValue());
      }
      List<Object> projectedItems = new ArrayList<>(items.size());
      for (Object item : items) {
        projectedItems.add(item instanceof Map<?, ?> row ? projectMap(row) : item);
      }
      result.put(ApiVocabulary.ITEMS, List.copyOf(projectedItems));
      return result;
    }
    return projectMap(map);
  }

  Map<String, Object> projectMap(Map<?, ?> source) {
    if (includeAll) {
      Map<String, Object> copy = new LinkedHashMap<>();
      for (Map.Entry<?, ?> entry : source.entrySet()) {
        if (entry.getValue() != null) {
          copy.put(String.valueOf(entry.getKey()), entry.getValue());
        }
      }
      return copy;
    }
    Map<String, Object> result = new LinkedHashMap<>();
    for (Map.Entry<String, ProjectionNode> entry : children.entrySet()) {
      String key = entry.getKey();
      Object value = source.get(key);
      if (value == null) continue;
      Object projected = projectValue(value, entry.getValue());
      if (projected != null) {
        result.put(key, projected);
      }
    }
    return result;
  }

  private static Object projectValue(Object value, ProjectionNode node) {
    if (node.includeAll()) return value;
    if (value instanceof Map<?, ?> map) {
      return node.projectMap(map);
    }
    if (value instanceof List<?> list) {
      List<Object> projected = new ArrayList<>(list.size());
      for (Object item : list) {
        if (item instanceof Map<?, ?> child) {
          projected.add(node.projectMap(child));
        }
      }
      return List.copyOf(projected);
    }
    return null;
  }

  private static final class Builder {
    private boolean includeAll;
    private final Map<String, Builder> children = new LinkedHashMap<>();

    void insert(String path, int start) {
      int separator = path.indexOf('.', start);
      if (separator < 0) {
        String segment = path.substring(start);
        Builder leaf = children.computeIfAbsent(segment, ignored -> new Builder());
        leaf.includeAll = true;
        return;
      }
      String segment = path.substring(start, separator);
      Builder child = children.computeIfAbsent(segment, ignored -> new Builder());
      child.insert(path, separator + 1);
    }

    ProjectionNode build() {
      if (includeAll) return ALL;
      Map<String, ProjectionNode> built = new LinkedHashMap<>();
      for (Map.Entry<String, Builder> entry : children.entrySet()) {
        built.put(entry.getKey(), entry.getValue().build());
      }
      return new ProjectionNode(false, built);
    }
  }
}
