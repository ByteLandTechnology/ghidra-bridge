package app.byteland.ghidra.service.datatype;

public record DataTypeCategoryResource(
    String path, String name, int categoryCount, int dataTypeCount) {}
