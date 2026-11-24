package app.byteland.ghidra.adapter.ghidra;

import java.util.Set;

/**
 * Checks whether {@code projection.fields} selects root or nested Ghidra attributes.
 */
public final class FieldProjections {
  private FieldProjections() {}

  public static boolean allows(Set<String> fields, String root) {
    if (fields == null || fields.contains(root)) return true;
    String prefix = root + ".";
    for (String field : fields) {
      if (field.startsWith(prefix)) return true;
    }
    return false;
  }

  public static boolean allowsSubfield(Set<String> fields, String root, String subfield) {
    if (fields == null || fields.contains(root)) return true;
    String path = root + "." + subfield;
    if (fields.contains(path)) return true;
    String prefix = path + ".";
    for (String field : fields) {
      if (field.startsWith(prefix)) return true;
    }
    return false;
  }
}
