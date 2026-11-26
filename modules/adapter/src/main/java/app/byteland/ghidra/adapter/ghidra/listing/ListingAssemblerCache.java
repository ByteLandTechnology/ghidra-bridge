package app.byteland.ghidra.adapter.ghidra.listing;

import ghidra.app.plugin.assembler.Assembler;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.assembler.AssemblyError;
import ghidra.program.model.listing.Program;
import java.util.Map;
import java.util.Objects;
import java.util.WeakHashMap;
import java.util.function.Function;

/**
 * Caches one Sleigh {@link Assembler} instance for each open {@link Program}.
 */
final class ListingAssemblerCache {
  private final Map<Program, Assembler> cache = new WeakHashMap<>();
  private final Function<Program, Assembler> factory;

  ListingAssemblerCache() {
    this(Assemblers::getAssembler);
  }

  ListingAssemblerCache(Function<Program, Assembler> factory) {
    this.factory = Objects.requireNonNull(factory, "factory");
  }

  synchronized Assembler get(Program program) {
    Objects.requireNonNull(program, "program");
    Assembler cached = cache.get(program);
    if (cached != null) {
      return cached;
    }
    Assembler created = createAssembler(program);
    cache.put(program, created);
    return created;
  }

  synchronized void releaseProgram(Program program) {
    if (program != null) {
      cache.remove(program);
    }
  }

  private Assembler createAssembler(Program program) {
    try {
      return Objects.requireNonNull(factory.apply(program), "assembler");
    } catch (UnsupportedOperationException | AssemblyError exception) {
      String detail = exception.getMessage();
      if (detail == null || detail.isBlank()) {
        detail = program.getLanguageID().getIdAsString();
      }
      String prefix =
          exception instanceof AssemblyError
              ? "unable to initialize Sleigh assembler: "
              : "program language does not support Sleigh assembly: ";
      throw new IllegalArgumentException(prefix + detail, exception);
    }
  }
}
