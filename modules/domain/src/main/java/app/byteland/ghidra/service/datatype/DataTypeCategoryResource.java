package app.byteland.ghidra.service.datatype;

/**
 * Metadata for a data type category in the program archive.
 *
 * @param path canonical category path
 * @param name category name
 * @param categoryCount number of direct subcategories
 * @param dataTypeCount number of direct data types
 */
public record DataTypeCategoryResource(
    String path, String name, int categoryCount, int dataTypeCount) {}
