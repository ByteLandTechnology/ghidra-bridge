package app.byteland.ghidra.adapter.ghidra;

import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.WeakHashMap;

/** Reads C++ names without changes to the program or its symbol IDs. */
public final class CppSymbolNames {
  private static final int CACHE_LIMIT = 4096;
  private static final Map<Program, Map<String, Optional<String>>> CACHES = new WeakHashMap<>();

  private CppSymbolNames() {}

  public static String demangled(Program program, String name, Address address) {
    if (!isMangled(name)) return null;
    Map<String, Optional<String>> cache = cacheFor(program);
    synchronized (cache) {
      Optional<String> known = cache.get(name);
      if (known != null) return known.orElse(null);
    }
    // The demangler can use an external process. Do not hold the lock during the call.
    String result = decode(program, name, address);
    synchronized (cache) {
      if (cache.size() >= CACHE_LIMIT) cache.remove(cache.keySet().iterator().next());
      cache.put(name, Optional.ofNullable(result));
    }
    return result;
  }

  public static boolean isMangled(String name) {
    return name != null
        && (name.startsWith("_Z") || name.startsWith("__Z") || name.startsWith("?"));
  }

  private static Map<String, Optional<String>> cacheFor(Program program) {
    synchronized (CACHES) {
      return CACHES.computeIfAbsent(program, ignored -> new LinkedHashMap<>(64, 0.75f, true));
    }
  }

  private static String decode(Program program, String name, Address address) {
    for (DemangledObject object : DemanglerUtil.demangle(program, name, address)) {
      String result = object.getSignature(false);
      if (result != null && !result.isBlank() && !result.equals(name)) return result;
    }
    return null;
  }
}
