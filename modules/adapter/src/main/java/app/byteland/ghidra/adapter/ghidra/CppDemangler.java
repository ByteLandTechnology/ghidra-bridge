package app.byteland.ghidra.adapter.ghidra;

import ghidra.app.util.demangler.DemangledObject;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import java.util.List;

/** Decodes mangled C++ symbol names for a Ghidra program. */
@FunctionalInterface
public interface CppDemangler {
  List<DemangledObject> demangle(Program program, String name, Address address);
}
