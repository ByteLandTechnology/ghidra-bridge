package app.byteland.ghidra.adapter.ghidra.listing;

import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.assembler.AssemblyError;
import ghidra.program.model.listing.Program;
import java.util.Map;
import java.util.WeakHashMap;

/**
 * Caches one Sleigh {@link Assembler} per open {@link Program} so repeated assembly requests reuse
 * compiled Sleigh grammar state.
 */
final class ListingAssemblerCache {
  private static final Map<Program, Assembler> CACHE = new WeakHashMap<>();

  private ListingAssemblerCache() {}

  static synchronized Assembler assemblerFor(Program program) {
    Assembler cached = CACHE.get(program);
    if (cached != null) {
      return cached;
    }
    try {
      Assembler created = Assemblers.getAssembler(program);
      CACHE.put(program, created);
      return created;
    } catch (UnsupportedOperationException | AssemblyError ex) {
      throw new IllegalArgumentException(
          "assembly is not supported for program language "
              + program.getLanguageID()
              + ": "
              + ex.getMessage(),
          ex);
    }
  }
}
