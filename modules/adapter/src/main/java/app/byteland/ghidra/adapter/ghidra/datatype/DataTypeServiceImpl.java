package app.byteland.ghidra.adapter.ghidra.datatype;

import app.byteland.ghidra.adapter.ghidra.GhidraDataTypeReferences;
import app.byteland.ghidra.adapter.ghidra.GhidraSession;
import app.byteland.ghidra.service.Page;
import app.byteland.ghidra.service.datatype.DataTypeCategoryResource;
import app.byteland.ghidra.service.datatype.DataTypePatch;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import app.byteland.ghidra.service.datatype.DataTypeResource;
import app.byteland.ghidra.service.datatype.DataTypeService;
import app.byteland.ghidra.service.datatype.FunctionSignature;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.Union;
import java.util.NoSuchElementException;

public final class DataTypeServiceImpl implements DataTypeService {
  private final GhidraSession context;

  public DataTypeServiceImpl(GhidraSession context) {
    this.context = context;
  }

  @Override
  public Page<DataTypeCategoryResource> listCategories(
      String categoryPath, int limit, String cursor) {
    return DataTypeQueries.listCategories(dataTypeManager(), categoryPath, limit, cursor);
  }

  @Override
  public DataTypeResource getDataType(String path) {
    return DataTypeDescriptions.detail(requireDataType(path));
  }

  @Override
  public Page<DataTypeResource> searchDataTypes(
      String query, String categoryPath, String kind, int limit, String cursor) {
    return DataTypeQueries.searchDataTypes(
        dataTypeManager(), query, categoryPath, kind, limit, cursor);
  }

  @Override
  public void createDataType(
      String categoryPath,
      DataTypeResource.Kind kind,
      String name,
      DataTypeReference baseType,
      int size,
      FunctionSignature signature) {
    DataTypeMutations.createDataType(
        dataTypeManager(),
        categoryPath,
        kind,
        name,
        baseType,
        size,
        signature,
        this::resolveDataTypeReference);
  }

  @Override
  public void patchDataType(String path, DataTypePatch patch) {
    DataType dataType = requireDataType(path);
    switch (patch) {
      case DataTypePatch.Struct structPatch -> {
        if (!(dataType instanceof Structure structure)) {
          throw new IllegalArgumentException("not a struct: " + dataType.getName());
        }
        StructMutations.edit(structure, structPatch, this::resolveDataTypeReference);
      }
      case DataTypePatch.Union unionPatch -> {
        if (!(dataType instanceof Union union)) {
          throw new IllegalArgumentException("not a union: " + dataType.getName());
        }
        UnionMutations.edit(union, unionPatch, this::resolveDataTypeReference);
      }
      case DataTypePatch.EnumPatch enumPatch -> {
        if (!(dataType instanceof ghidra.program.model.data.Enum enumType)) {
          throw new IllegalArgumentException("not an enum: " + dataType.getName());
        }
        EnumMutations.edit(enumType, enumPatch);
      }
    }
  }

  @Override
  public boolean deleteDataType(String path) {
    return dataTypeManager().remove(requireDataType(path));
  }

  private DataType requireDataType(String path) {
    DataType dataType = DataTypeResolver.resolve(dataTypeManager(), path);
    if (dataType == null) throw new NoSuchElementException("data type not found: " + path);
    return dataType;
  }

  private DataTypeManager dataTypeManager() {
    return context.currentProgram().getDataTypeManager();
  }

  private DataType resolveDataTypeReference(DataTypeReference reference) {
    return GhidraDataTypeReferences.resolve(dataTypeManager(), reference);
  }
}
