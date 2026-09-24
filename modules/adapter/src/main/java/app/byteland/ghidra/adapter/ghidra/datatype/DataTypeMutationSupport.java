package app.byteland.ghidra.adapter.ghidra.datatype;

import app.byteland.ghidra.adapter.ghidra.GhidraDataTypeReferences;
import app.byteland.ghidra.service.datatype.DataTypeReference;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.util.exception.DuplicateNameException;
import java.util.function.Function;

final class DataTypeMutationSupport {
  private DataTypeMutationSupport() {}

  static DataType resolveFieldDataType(
      DataTypeReference reference, Function<DataTypeReference, DataType> resolver) {
    DataTypeReference selected = reference == null ? DataTypeReference.named("byte") : reference;
    DataType dataType = resolver.apply(selected);
    if (dataType == null) throw new IllegalArgumentException("unknown data type: " + selected);
    requireCompositeValueType(dataType, "data_type");
    return dataType;
  }

  static DataType requireDataType(
      Function<DataTypeReference, DataType> resolver, DataTypeReference reference) {
    DataType dataType = resolver.apply(reference);
    if (dataType == null) throw new IllegalArgumentException("unknown data type: " + reference);
    requireCompositeValueType(dataType, "data_type");
    return dataType;
  }

  static int fieldLength(DataType dataType, Integer explicitLength, Integer fallback) {
    requireCompositeValueType(dataType, "data_type");
    if (explicitLength != null) {
      if (dataType instanceof Array) {
        throw new IllegalArgumentException("array data_type and length are mutually exclusive");
      }
      if (explicitLength <= 0) throw new IllegalArgumentException("length must be positive");
      return explicitLength;
    }
    if (fallback != null && fallback > 0) return fallback;
    return dataType.getLength() > 0 ? dataType.getLength() : 1;
  }

  private static void requireCompositeValueType(DataType dataType, String target) {
    if (GhidraDataTypeReferences.isBareFunctionDefinition(dataType)) {
      throw new IllegalArgumentException(
          target + " must use kind=pointer for a function definition");
    }
  }

  static void applyMetadataPatch(DataTypeComponent component, String newName, String newComment) {
    if (newName != null && !newName.equals(component.getFieldName())) {
      try {
        component.setFieldName(newName);
      } catch (Exception exception) {
        if (exception instanceof DuplicateNameException) {
          throw new IllegalArgumentException("duplicate field name: " + newName, exception);
        }
        if (exception instanceof RuntimeException runtime) throw runtime;
        throw new IllegalStateException("cannot rename data type field", exception);
      }
    }
    if (!String.valueOf(component.getComment()).equals(String.valueOf(newComment))) {
      component.setComment(newComment);
    }
  }
}
