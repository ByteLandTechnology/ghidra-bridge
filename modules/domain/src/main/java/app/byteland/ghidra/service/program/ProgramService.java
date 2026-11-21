package app.byteland.ghidra.service.program;

import app.byteland.ghidra.service.Page;
import java.util.Set;

/**
 * Gives access to program metadata, address spaces, and export operations.
 */
public interface ProgramService {
  /** Returns metadata for the active Ghidra program. */
  ProgramResource getProgram();

  /** Returns metadata for the active Ghidra program with an optional field projection. */
  default ProgramResource getProgram(Set<String> fields) {
    return getProgram();
  }

  /** Returns one page of address spaces. */
  Page<AddressSpaceResource> getAddressSpaces(int limit, String cursor);

  /** Returns one page of address spaces with an optional field projection. */
  default Page<AddressSpaceResource> getAddressSpaces(
      int limit, String cursor, Set<String> fields) {
    return getAddressSpaces(limit, cursor);
  }

  /** Returns compiler and architecture language details. */
  ProgramLanguageResource getLanguageInfo();

  /** Returns compiler and architecture language details with an optional field projection. */
  default ProgramLanguageResource getLanguageInfo(Set<String> fields) {
    return getLanguageInfo();
  }

  /** Saves program changes to the project database. */
  void saveProgram();
}
