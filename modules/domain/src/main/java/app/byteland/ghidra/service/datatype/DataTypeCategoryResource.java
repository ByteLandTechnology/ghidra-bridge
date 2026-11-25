package app.byteland.ghidra.service.datatype;

/**
 * Summary of a data type category in a program data type manager.
 *
 * @param path full category path
 * @param name category name
 * @param categoryCount number of direct child categories
 * @param dataTypeCount number of direct data types in the category
 */
public record DataTypeCategoryResource(
    String path, String name, int categoryCount, int dataTypeCount) {}
