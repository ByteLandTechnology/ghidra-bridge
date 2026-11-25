package app.byteland.ghidra.service.program;

import app.byteland.ghidra.service.Page;

/**
 * Gives access to program metadata, address spaces, and export operations.
 */
public interface ProgramService {
  /**
   * Returns metadata for the active Ghidra program.
   *
   * @return active program summary resource
   */
  ProgramResource getProgram();

  /**
   * Returns one page of address spaces.
   *
   * @param limit maximum items to return
   * @param cursor optional pagination cursor
   * @return page of address space resources
   */
  Page<AddressSpaceResource> getAddressSpaces(int limit, String cursor);

  /**
   * Returns compiler and architecture language details.
   *
   * @return program language resource
   */
  ProgramLanguageResource getLanguageInfo();

  /** Saves program changes to the project database. */
  void saveProgram();
}
