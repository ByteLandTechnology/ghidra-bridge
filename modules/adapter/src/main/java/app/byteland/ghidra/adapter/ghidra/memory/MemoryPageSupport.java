package app.byteland.ghidra.adapter.ghidra.memory;

import ghidra.program.model.mem.MemoryBlock;
import java.util.Locale;

final class MemoryPageSupport {
  private MemoryPageSupport() {}

  static String normalizeNameFilter(String nameFilterRaw) {
    return nameFilterRaw == null || nameFilterRaw.isBlank()
        ? null
        : nameFilterRaw.toLowerCase(Locale.ROOT);
  }

  static boolean matchesFilters(
      MemoryBlock block, Boolean execute, Boolean write, Boolean read, String normalizedName) {
    if (execute != null && block.isExecute() != execute) {
      return false;
    }
    if (write != null && block.isWrite() != write) {
      return false;
    }
    if (read != null && block.isRead() != read) {
      return false;
    }
    return normalizedName == null
        || block.getName().toLowerCase(Locale.ROOT).contains(normalizedName);
  }
}
