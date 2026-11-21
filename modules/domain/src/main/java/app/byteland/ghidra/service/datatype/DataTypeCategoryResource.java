package app.byteland.ghidra.service.datatype;

/**
 * Summarizes a Ghidra data type category and its child counts.
 *
 * @param path absolute slash-prefixed category path
 * @param name simple category name
 * @param categoryCount direct child category count
 * @param dataTypeCount direct child data type count
 */
public record DataTypeCategoryResource(
    String path, String name, int categoryCount, int dataTypeCount) {}
