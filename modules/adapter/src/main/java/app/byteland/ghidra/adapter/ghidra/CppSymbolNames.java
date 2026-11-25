package app.byteland.ghidra.adapter.ghidra;

import ghidra.app.util.demangler.DemanglerUtil;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;

/** Reads C++ names without changes to the program or its symbol IDs. */
public final class CppSymbolNames {
  private CppSymbolNames() {}

  public static String demangled(
      GhidraSession session, Program program, String name, Address address) {
    if (session != null) {
      return session.cppSymbols().demangled(program, name, address);
    }
    return demangled(program, name, address);
  }

  public static String demangled(Program program, String name, Address address) {
    if (!isMangled(name) || program == null) return null;
    return CppSymbolIndex.decode(DemanglerUtil::demangle, program, name, address).demangledName();
  }

  public static boolean isMangled(String name) {
    return name != null
        && (name.startsWith("_Z") || name.startsWith("__Z") || name.startsWith("?"));
  }
}
