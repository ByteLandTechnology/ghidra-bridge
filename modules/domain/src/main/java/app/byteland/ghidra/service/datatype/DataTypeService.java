package app.byteland.ghidra.service.datatype;

import app.byteland.ghidra.service.Page;

/**
 * Manages data types, structures, and category hierarchies.
 */
public interface DataTypeService {
  /**
   * Returns child categories under a category path.
   *
   * @param categoryPath root path to inspect
   * @param limit maximum items to return
   * @param cursor optional continuation token
   * @return a page of child category resources
   */
  Page<DataTypeCategoryResource> listCategories(String categoryPath, int limit, String cursor);

  /**
   * Returns metadata for a data type by path.
   *
   * @param path full data type path
   * @return data type resource metadata
   */
  DataTypeResource getDataType(String path);

  /**
   * Searches data types matching query filters.
   *
   * @param query text filter for name search
   * @param categoryPath optional parent category filter
   * @param kind optional data type kind filter
   * @param limit maximum items to return
   * @param cursor optional continuation token
   * @return a page of matching data type resources
   */
  Page<DataTypeResource> searchDataTypes(
      String query, String categoryPath, String kind, int limit, String cursor);

  /**
   * Creates a data type in the program data manager. A function definition at the same path is
   * overwritten.
   *
   * @param categoryPath destination category folder
   * @param kind data type classification kind
   * @param name name of the new data type
   * @param baseType underlying referenced type
   * @param size initial struct length or enum byte width; 0 or less selects the default
   * @param signature optional function signature definition
   */
  void createDataType(
      String categoryPath,
      DataTypeResource.Kind kind,
      String name,
      DataTypeReference baseType,
      int size,
      FunctionSignature signature);

  /**
   * Updates an existing data type definition.
   *
   * @param path full path of data type to modify
   * @param patch modification instructions and fields
   */
  void patchDataType(String path, DataTypePatch patch);

  /**
   * Deletes a data type by its full path.
   *
   * @param path full path of data type to delete
   * @return true if data type was removed
   */
  boolean deleteDataType(String path);
}
