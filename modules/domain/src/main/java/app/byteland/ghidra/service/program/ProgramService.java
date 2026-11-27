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

  /** Returns one page of imported external functions and symbols. */
  Page<ImportResource> listImports(ImportQuery query);

  /** Returns one page of exported entry points in address order. */
  Page<ExportResource> listExports(ExportQuery query);

  /** Returns one page of external entry points in address order. */
  Page<ExportResource> listEntryPoints(ExportQuery query);

  /** Returns compiler and architecture language details. */
  ProgramLanguageResource getLanguageInfo();

  /** Saves program changes to the project database. */
  void saveProgram();

  /**
   * Parameters that filter and paginate program imports.
   */
  record ImportQuery(
      String name,
      String library,
      boolean regex,
      String nameRegex,
      String libraryRegex,
      int limit,
      String cursor) {}

  /**
   * Parameters that filter and paginate program exports or entry points.
   */
  record ExportQuery(
      String name,
      String namespace,
      boolean regex,
      String nameRegex,
      Boolean isFunction,
      int limit,
      String cursor) {}
}
