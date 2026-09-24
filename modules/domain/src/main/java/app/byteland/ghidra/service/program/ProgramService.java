package app.byteland.ghidra.service.program;

import app.byteland.ghidra.service.Page;

/**
 * Gives access to program metadata, address spaces, and export operations.
 */
public interface ProgramService {
  /** Returns metadata for the active Ghidra program. */
  ProgramResource getProgram();

  /** Returns one page of address spaces. */
  Page<AddressSpaceResource> getAddressSpaces(int limit, String cursor);

  /** Returns compiler and architecture language details. */
  ProgramLanguageResource getLanguageInfo();

  /** Saves program changes to the project database. */
  void saveProgram();
}
