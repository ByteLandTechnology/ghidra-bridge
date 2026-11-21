package app.byteland.ghidra.service.datatype;

/**
 * Summarizes a data type archive category path and child counts.
 *
 * @param path absolute category path
 * @param name category leaf name
 * @param categoryCount direct subcategory count
 * @param dataTypeCount direct data type count
 */
public record DataTypeCategoryResource(
    String path, String name, int categoryCount, int dataTypeCount) {}
