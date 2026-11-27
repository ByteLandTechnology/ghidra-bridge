package app.byteland.ghidra.api;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

final class FieldSelection {
  private static final Entry[] EMPTY_ENTRIES = new Entry[0];
  static final FieldSelection ALL = new FieldSelection(Map.of(), EMPTY_ENTRIES, true);
  private static final FieldSelection NONE = new FieldSelection(Map.of(), EMPTY_ENTRIES, false);

  private final Map<String, FieldSelection> children;
  private final Entry[] entries;
  private final boolean selectAll;

  private FieldSelection(Map<String, FieldSelection> children, Entry[] entries, boolean selectAll) {
    this.children = children;
    this.entries = entries;
    this.selectAll = selectAll;
  }

  static FieldSelection from(Set<String> paths) {
    if (paths == null) {
      return ALL;
    }
    if (paths.isEmpty()) {
      return NONE;
    }
    NodeBuilder root = new NodeBuilder(paths.size());
    for (String path : paths) {
      insert(root, Objects.requireNonNull(path, "path"), 0);
    }
    return root.build();
  }

  boolean selectsAll() {
    return selectAll;
  }

  Map<String, FieldSelection> children() {
    return children;
  }

  Entry[] entries() {
    return entries;
  }

  FieldSelection child(String key) {
    return selectAll ? ALL : children.get(key);
  }

  boolean containsKey(String key) {
    return selectAll || children.containsKey(key);
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) {
      return true;
    }
    if (!(other instanceof FieldSelection that)) {
      return false;
    }
    return selectAll == that.selectAll && children.equals(that.children);
  }

  @Override
  public int hashCode() {
    return Objects.hash(selectAll, children);
  }

  record Entry(String key, FieldSelection selection) {}

  private static void insert(NodeBuilder node, String path, int start) {
    int separator = path.indexOf('.', start);
    if (separator < 0) {
      String key = start == 0 ? path : path.substring(start);
      node.children.put(key, ALL);
      return;
    }
    String segment = path.substring(start, separator);
    Object existing = node.children.get(segment);
    if (existing == ALL) {
      return;
    }
    NodeBuilder child;
    if (existing instanceof NodeBuilder existingBuilder) {
      child = existingBuilder;
    } else {
      child = new NodeBuilder(4);
      node.children.put(segment, child);
    }
    insert(child, path, separator + 1);
  }

  private static final class NodeBuilder {
    private final Map<String, Object> children;

    NodeBuilder(int expectedSize) {
      this.children = LinkedHashMap.newLinkedHashMap(expectedSize);
    }

    @SuppressWarnings("unchecked")
    FieldSelection build() {
      if (children.isEmpty()) {
        return NONE;
      }
      Entry[] builtEntries = new Entry[children.size()];
      int index = 0;
      for (Map.Entry<String, Object> entry : children.entrySet()) {
        FieldSelection childSelection;
        if (entry.getValue() instanceof NodeBuilder childBuilder) {
          childSelection = childBuilder.build();
          entry.setValue(childSelection);
        } else {
          childSelection = (FieldSelection) entry.getValue();
        }
        builtEntries[index++] = new Entry(entry.getKey(), childSelection);
      }
      return new FieldSelection(
          Collections.unmodifiableMap((Map<String, FieldSelection>) (Map<?, ?>) children),
          builtEntries,
          false);
    }
  }
}
