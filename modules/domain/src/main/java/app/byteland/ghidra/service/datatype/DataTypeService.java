package app.byteland.ghidra.service.datatype;

import app.byteland.ghidra.service.Page;
import java.util.List;

/**
 * Manages data types, structures, and category hierarchies.
 */
public interface DataTypeService {
  int MAX_STRUCT_SIZE = 1_048_576;
  int MAX_DEFINED_COMPONENTS = 1_000;

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
   * Searches for data types that match query filters.
   *
   * @param query text filter for name search
   * @param categoryPath optional parent category filter
   * @param kind optional data type kind filter
   * @param limit maximum items to return
   * @param cursor optional continuation token
   * @return a page of data type resources that match the query
   */
  Page<DataTypeResource> searchDataTypes(
      String query, String categoryPath, String kind, int limit, String cursor);

  /**
   * Creates a data type in the program data manager.
   * The operation replaces a function definition or typedef at the same path.
   *
   * @param categoryPath destination category folder
   * @param kind data type classification kind
   * @param name name of the new data type
   * @param baseType referenced base type
   * @param size initial struct length or enum byte width. A value of 0 or less selects the default
   * @param signature optional function signature definition
   */
  default void createDataType(
      String categoryPath,
      DataTypeResource.Kind kind,
      String name,
      DataTypeReference baseType,
      int size,
      FunctionSignature signature) {
    createDataType(categoryPath, kind, name, baseType, size, signature, null, null);
  }

  /**
   * Creates a data type in the program data manager with optional initial members.
   * The operation replaces a function definition or typedef at the same path.
   *
   * @param categoryPath destination category folder
   * @param kind data type classification kind
   * @param name name of the new data type
   * @param baseType referenced base type
   * @param size initial struct length or enum byte width. A value of 0 or less selects the default
   * @param signature optional function signature definition
   * @param fields optional initial composite fields for struct or union
   * @param values optional initial values for enum
   */
  void createDataType(
      String categoryPath,
      DataTypeResource.Kind kind,
      String name,
      DataTypeReference baseType,
      int size,
      FunctionSignature signature,
      List<DataTypePatch.CompositeField> fields,
      List<DataTypePatch.EnumValue> values);

  /**
   * Updates a data type definition that exists.
   *
   * @param path full path of data type to modify
   * @param patch modification instructions and fields
   */
  void patchDataType(String path, DataTypePatch patch);

  /**
   * Deletes a data type by its full path.
   *
   * @param path full path of data type to delete
   * @return true if the method removes the data type
   */
  boolean deleteDataType(String path);
}
