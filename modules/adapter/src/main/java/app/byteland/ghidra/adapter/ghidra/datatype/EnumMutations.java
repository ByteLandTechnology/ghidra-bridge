package app.byteland.ghidra.adapter.ghidra.datatype;

import app.byteland.ghidra.service.datatype.DataTypeMutationValidationException;
import app.byteland.ghidra.service.datatype.DataTypePatch;
import java.util.List;
import java.util.NoSuchElementException;

final class EnumMutations {
  private EnumMutations() {}

  static void edit(ghidra.program.model.data.Enum enumType, DataTypePatch.EnumPatch patch) {
    remove(enumType, patch.removeValues());
    patch(enumType, patch.renameValues(), true, "/patch/rename_values");
    patch(enumType, patch.updateValues(), false, "/patch/update_values");
    if (patch.addValues() != null) {
      for (DataTypePatch.EnumValue value : patch.addValues()) {
        enumType.add(
            value.name() == null ? "VALUE" : value.name(),
            value.value() == null ? 0 : value.value());
      }
    }
  }

  private static void remove(
      ghidra.program.model.data.Enum enumType, List<DataTypePatch.EnumValue> selectors) {
    if (selectors == null) return;
    for (int index = 0; index < selectors.size(); index++) {
      DataTypePatch.EnumValue selector = selectors.get(index);
      if (selector.name() != null) {
        if (selector.value() == null
            || (enumType.contains(selector.name())
                && enumType.getValue(selector.name()) == selector.value())) {
          if (enumType.contains(selector.name())) enumType.remove(selector.name());
        }
      } else if (selector.value() != null) {
        String[] names = enumType.getNames(selector.value());
        if (names != null) for (String name : names.clone()) enumType.remove(name);
      } else {
        throw new DataTypeMutationValidationException(
            "/patch/remove_values/" + index, "enum selector requires name or value");
      }
    }
  }

  private static void patch(
      ghidra.program.model.data.Enum enumType,
      List<DataTypePatch.EnumValue> updates,
      boolean renameOnly,
      String targetPrefix) {
    if (updates == null) return;
    for (int index = 0; index < updates.size(); index++) {
      DataTypePatch.EnumValue update = updates.get(index);
      String itemTarget = targetPrefix + "/" + index;
      if (update.name() == null) {
        throw new DataTypeMutationValidationException(
            itemTarget + "/name", itemTarget + "/name is required");
      }
      if (!enumType.contains(update.name())) {
        throw new NoSuchElementException("enum value not found: " + update.name());
      }
      if (renameOnly && update.newName() == null) {
        throw new DataTypeMutationValidationException(
            itemTarget + "/new_name", itemTarget + "/new_name is required");
      }
      String name = update.newName() == null ? update.name() : update.newName();
      long value =
          renameOnly || update.value() == null ? enumType.getValue(update.name()) : update.value();
      String comment = enumType.getComment(update.name());
      if (update.name().equals(name) && enumType.getValue(update.name()) == value) continue;
      enumType.remove(update.name());
      if (comment == null) enumType.add(name, value);
      else enumType.add(name, value, comment);
    }
  }
}
